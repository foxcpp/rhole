package main

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
	"golang.org/x/sys/unix"
)

type Config struct {
	Listen                string   `toml:"listen"`
	Downstreams           []string `toml:"downstreams"`
	DownstreamTimeoutSecs int      `toml:"downstream_timeout_secs"`
	Blacklists            []string `toml:"blacklists"`
	Whitelists            []string `toml:"whitelists"`
}

func normalize(domain string) string {
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")
	norm, err := idna.ToASCII(domain)
	if err != nil {
		return domain
	}
	return norm
}

func readLists(paths []string) (map[string]struct{}, error) {
	list := make(map[string]struct{}, 50000)

	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		scnr := bufio.NewScanner(file)
		hosts := false
		for scnr.Scan() {
			//if strings.HasPrefix(scnr.Text(), "127.0.0.1 ") && !hosts {
			//	fmt.Fprintf(os.Stderr, "%s detected as a hosts-style list, ignoring IP and blocking all domains\n", path)
			//	hosts = true
			//}

			line := scnr.Text()
			if indx := strings.Index(line, "#"); indx != -1 {
				line = line[:indx]
			}
			parts := strings.Fields(line)

			if hosts {
				if len(parts) == 0 { // empty line
					continue
				}
				parts = parts[1:]
			}

			for _, part := range parts {
				list[normalize(part)] = struct{}{}
			}
		}
		if err := scnr.Err(); err != nil {
			return nil, err
		}
	}

	return list, nil
}

type Server struct {
	serverIndx uint32

	blockedCnt uint32
	totalCnt   uint32

	s           *dns.Server
	cl          dns.Client
	blacklist   map[string]struct{}
	downstreams []string
}

func (s *Server) ServeDNS(w dns.ResponseWriter, m *dns.Msg) {
	reply := new(dns.Msg)

	if m.MsgHdr.Opcode != dns.OpcodeQuery {
		reply.SetRcode(m, dns.RcodeRefused)
		if err := w.WriteMsg(reply); err != nil {
			log.Printf("WriteMsg: %v", err)
		}
		return
	}

	reply.SetReply(m)
	reply.RecursionAvailable = true

	q := m.Question[0]

	if q.Qclass != dns.ClassINET {
		reply.SetRcode(m, dns.RcodeNotImplemented)
		if err := w.WriteMsg(reply); err != nil {
			log.Printf("WriteMsg: %v", err)
		}
		return
	}

	atomic.AddUint32(&s.totalCnt, 1)

	key := normalize(q.Name)
	if _, ok := s.blacklist[key]; ok {
		// Synthesize NXDOMAIN.
		reply.Rcode = dns.RcodeNameError
		reply.RecursionAvailable = true
		reply.Ns = []dns.RR{
			&dns.SOA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeSOA,
					Class:  dns.ClassINET,
					Ttl:    9999,
				},
				Ns:      "invalid.",
				Mbox:    "hostmaster.invalid.",
				Serial:  1,
				Refresh: 900,
				Retry:   900,
				Expire:  1800,
				Minttl:  60,
			},
		}
		atomic.AddUint32(&s.blockedCnt, 1)

		if err := w.WriteMsg(reply); err != nil {
			log.Printf("WriteMsg: %v", err)
		}
		return
	}

	downReply, err := s.exchange(m)
	if err != nil {
		log.Println("Downstream error:", err)
		reply.SetRcode(m, dns.RcodeServerFailure)
		if err := w.WriteMsg(reply); err != nil {
			log.Printf("WriteMsg: %v", err)
		}
		return
	}
	if err := w.WriteMsg(downReply); err != nil {
		log.Printf("WriteMsg: %v", err)
	}
}

func isLoopback(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func (s *Server) exchange(msg *dns.Msg) (*dns.Msg, error) {
	offset := int(atomic.AddUint32(&s.serverIndx, 1) % uint32(len(s.downstreams)))
	if offset < 0 { // attempt to deal with integer overflows on 32-bit platforms
		offset = (-offset) % len(s.downstreams)
	}
	downstream := s.downstreams[offset]

	resp, _, err := s.cl.Exchange(msg, net.JoinHostPort(downstream, "53"))
	if err != nil {
		return nil, err
	}

	if resp.Rcode != dns.RcodeSuccess {
		return resp, nil
	}

	// Diregard AD flags from non-local resolvers, likely they are
	// communicated with using an insecure channel and so flags can be
	// tampered with.
	if !isLoopback(downstream) {
		resp.AuthenticatedData = false
	}

	return resp, nil
}

func NewServer(listen string, blacklist map[string]struct{}, downstreams []string, timeout time.Duration) (*Server, error) {
	tcpL, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	udpL, err := net.ListenPacket("udp", listen)
	if err != nil {
		return nil, err
	}

	srv := &Server{
		cl: dns.Client{
			Timeout: timeout,
		},
		blacklist:   blacklist,
		downstreams: downstreams,
	}
	srv.s = &dns.Server{
		Listener:   tcpL,
		PacketConn: udpL,
		Handler:    srv,
	}

	return srv, nil
}

func (s *Server) Serve() {
	s.s.ActivateAndServe()
}

func (s *Server) Close() {
	s.s.Shutdown()
}

func main() {
	cfgPath := "/etc/rhole.toml"
	switch len(os.Args) {
	case 1:
	case 2:
		cfgPath = os.Args[1]
	default:
		fmt.Fprintf(os.Stderr, "Usage: %s [config path]\n", os.Args[0])
		os.Exit(2)
	}

	log.SetFlags(0)

	var cfg Config
	_, err := toml.DecodeFile(cfgPath, &cfg)
	if err != nil {
		log.Println(err)
		os.Exit(2)
	}

	black, err := readLists(cfg.Blacklists)
	if err != nil {
		log.Println("Blacklist read failed:", err)
		os.Exit(2)
	}
	white, err := readLists(cfg.Whitelists)
	if err != nil {
		log.Println("Whitelist read failed:", err)
		os.Exit(2)
	}
	for ent := range white {
		delete(black, ent)
	}
	white = nil // free extra memory if whitelist is big
	log.Println("Blocking", len(black), "domains")

	if cfg.DownstreamTimeoutSecs == 0 {
		cfg.DownstreamTimeoutSecs = 5
	}

	s, err := NewServer(cfg.Listen, black, cfg.Downstreams, time.Duration(cfg.DownstreamTimeoutSecs)*time.Second)
	if err != nil {
		log.Println("Server init failed:", err)
		os.Exit(2)
	}

	go s.Serve()
	log.Println("Listening on", cfg.Listen)
	defer s.Close()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, unix.SIGTERM, unix.SIGUSR1)

	for {
		sig := <-ch
		if sig.String() == unix.SIGUSR1.String() {
			blocked := atomic.LoadUint32(&s.blockedCnt)
			total := atomic.LoadUint32(&s.totalCnt)
			log.Printf("Blocked %d out of %d queries (%v%%)", blocked, total, math.Round(float64(blocked)/float64(total)*100.0))
			continue
		}
		return
	}
}
