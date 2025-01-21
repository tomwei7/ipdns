# ipdns

simple dns server for extracting ip addresses from a domain name, e.g. 192-168-1-1.example.com -> 192.168.1.1

### Usage

```
Usage of ./bin/ipdns:
  -access-log
        enable access log
  -domain string
        domain name to match
  -listen string
        dns server listen address (default ":5353")
  -resolv-file string
        resolv.conf file path (default "/etc/resolv.conf")
  -timeout duration
        timeout for query each upstream dns server (default 5s)
  -ttl int
        TTL for response (default 300)
  -upstream string
        upstream dns server
```
