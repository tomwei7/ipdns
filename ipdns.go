package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	Log = log.New(os.Stderr, "[ipdns] ", log.LstdFlags)
)

// Config is a struct to hold the command line flags
type Config struct {
	// Listen dns server listen address
	// default: 5353
	Listen string
	// Domain domain name to match
	Domain string
	// Upstream upstream dns server, multiple servers separated by comma
	// if not set, use system dns server
	Upstream string
	// ResolvFile resolv.conf file path
	// default: /etc/resolv.conf
	ResolvFile string
	// Timeout timeout for query upstream dns server
	// it try next dns server if timeout
	Timeout time.Duration
	// TTL TTL for response
	// default: 300
	TTL int
	// AccessLog enable access log
	AccessLog bool
}

func (c *Config) Validate() error {
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	if c.Domain == "" {
		return errors.New("domain is required")
	}
	if c.Upstream == "" {
		_, err := readResolvFile(c.ResolvFile)
		if err != nil {
			return err
		}
	}
	if c.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if c.TTL <= 0 {
		return errors.New("ttl must be positive")
	}
	return nil
}

func (f *Config) AddFlags(flagSet *flag.FlagSet) {
	flagSet.StringVar(&f.Listen, "listen", ":5353", "dns server listen address")
	flagSet.StringVar(&f.Domain, "domain", "", "domain name to match")
	flagSet.StringVar(&f.Upstream, "upstream", "", "upstream dns server")
	flagSet.StringVar(&f.ResolvFile, "resolv-file", "/etc/resolv.conf", "resolv.conf file path")
	flagSet.DurationVar(&f.Timeout, "timeout", 5*time.Second, "timeout for query each upstream dns server")
	flagSet.IntVar(&f.TTL, "ttl", 300, "TTL for response")
	flagSet.BoolVar(&f.AccessLog, "access-log", false, "enable access log")
}

// readResolvFile reads resolv.conf file and returns dns server addresses
func readResolvFile(file string) ([]string, error) {
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	buf := bufio.NewReader(fd)
	var servers []string
	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		servers = append(servers, fields[1])
	}
	return servers, nil
}

func addDefaultPort(nameservers []string) []string {
	for idx, server := range nameservers {
		if strings.Contains(server, ":") {
			continue
		}
		nameservers[idx] = net.JoinHostPort(server, "53")
	}
	return nameservers
}

type DNSHandler struct {
	cfg *Config
	// nameservers upstream dns servers
	nameservers []string
	// client dns client to query upstream dns server
	client *dns.Client
}

func NewDNSHandler(cfg *Config) (*DNSHandler, error) {
	var nameservers []string
	if cfg.Upstream != "" {
		nameservers = strings.Split(cfg.Upstream, ",")
		Log.Printf("use upstream dns servers %s", strings.Join(nameservers, ", "))
	} else {
		servers, err := readResolvFile(cfg.ResolvFile)
		if err != nil {
			return nil, err
		}
		nameservers = servers
		Log.Printf("use system dns servers %s", strings.Join(nameservers, ", "))
	}
	// dns client require server address with port
	nameservers = addDefaultPort(nameservers)

	client := &dns.Client{Net: "udp", Timeout: cfg.Timeout}
	return &DNSHandler{
		cfg:         cfg,
		nameservers: nameservers,
		client:      client,
	}, nil
}

func buildA(name string, ip net.IP, ttl int) *dns.A {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    uint32(ttl),
		},
		A: ip,
	}
}

// trimDomainDot trims the trailing dot of domain name
func trimDomainDot(domain string) string {
	if len(domain) > 0 && domain[len(domain)-1] == '.' {
		return domain[:len(domain)-1]
	}
	return domain
}

func validateReq(r *dns.Msg) error {
	if r.Opcode != dns.OpcodeQuery {
		return fmt.Errorf("invalid opcode %d", r.Opcode)
	}
	if len(r.Question) != 1 {
		return fmt.Errorf("invalid question count %d", len(r.Question))
	}
	return nil
}

func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := h.handleReq(r)
	h.logAccess(m, r)
	w.WriteMsg(m)
}

func (h *DNSHandler) handleReq(r *dns.Msg) *dns.Msg {
	if err := validateReq(r); err != nil {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		return m
	}
	// dns2ip only handle A query for specific domain suffix
	// forward other queries to upstream dns server
	if r.Question[0].Qtype != dns.TypeA ||
		!strings.HasSuffix(trimDomainDot(r.Question[0].Name), h.cfg.Domain) {
		return h.forward(r)
	}
	return h.dns2ip(r)
}

// forward forwards the query to upstream dns server
func (h *DNSHandler) forward(r *dns.Msg) *dns.Msg {
	for _, server := range h.nameservers {
		m, _, err := h.client.Exchange(r, server)
		if err != nil {
			continue
		}
		return m
	}
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	return m
}

func (h *DNSHandler) dns2ip(r *dns.Msg) *dns.Msg {
	name := r.Question[0].Name
	if name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	ipPrefix := strings.TrimSuffix(name, h.cfg.Domain)
	// ip in domain name may use '-' instead of '.'
	ipPrefix = strings.Replace(ipPrefix, "-", ".", -1)
	ip := net.ParseIP(ipPrefix)
	m := new(dns.Msg)
	if ip == nil {
		m.SetRcode(r, dns.RcodeNameError)
	} else {
		m.SetReply(r)
		m.Answer = append(m.Answer, buildA(name, ip, h.cfg.TTL))
	}
	return m
}

func joinAnswer(ans []dns.RR, sep string) string {
	var s []string
	for _, a := range ans {
		s = append(s, strings.Replace(a.String(), "\t", " ", -1))
	}
	if len(s) == 0 {
		return "<nil>"
	}
	return strings.Join(s, sep)
}

func joinQuestion(qs []dns.Question, sep string) string {
	var s []string
	for _, q := range qs {
		s = append(s, strings.Replace(q.String(), "\t", " ", -1))
	}
	if len(s) == 0 {
		return "<nil>"
	}
	return strings.Join(s, sep)
}

func (h *DNSHandler) logAccess(m *dns.Msg, r *dns.Msg) {
	if !h.cfg.AccessLog {
		return
	}
	Log.Printf("QUERY Question %s, Answer: %s Rcode: %d",
		joinQuestion(r.Question, ", "), joinAnswer(m.Answer, ", "), m.Rcode)
}

func main() {
	cfg := new(Config)
	cfg.AddFlags(flag.CommandLine)
	flag.Parse()
	if err := cfg.Validate(); err != nil {
		Log.Fatalf("invalid config %s", err)
	}

	handler, err := NewDNSHandler(cfg)
	if err != nil {
		Log.Fatalf("create dns handler error %s", err)
	}

	server := &dns.Server{Addr: cfg.Listen, Net: "udp", Handler: handler}
	Log.Printf("dns server listen on %s", cfg.Listen)
	if err := server.ListenAndServe(); err != nil {
		Log.Fatalf("dns server listen error %s", err)
	}
}
