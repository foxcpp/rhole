# rhole

> Minimal DNS forwarder with blacklist support.

_Minimal_, this utility does not implement caching, DoT, DoH or DNSSEC. There
are software packages that can do that already and can do that better, check
them all.

```
go get -u github.com/foxcpp/rhole
rhole /etc/rhole.toml
```

rhole.toml example:
```
listen = "127.0.0.1:53"
downstreams = ["1.1.1.1", "9.9.9.10"]
blacklists = ["/etc/bad_domains"]
```

Btw, ρ (rho) is the next Greek letter after pi.
pi-hole is nice too.
