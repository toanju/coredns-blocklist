package blocklist

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/miekg/dns"
)

func init() { plugin.Register("blocklist", setup) }

func periodicHostsUpdate(bl *Blocklist) chan bool {
	parseChan := make(chan bool)

	if bl.reload == 0 {
		return parseChan
	}

	go func() {
		ticker := time.NewTicker(bl.reload)
		defer ticker.Stop()
		for {
			select {
			case <-parseChan:
				return
			case <-ticker.C:
				bl.readBlocklist()
			}
		}
	}()
	return parseChan
}

func setup(c *caddy.Controller) error {
	bl, err := parseBlocklist(c)
	if err != nil {
		return plugin.Error("blocklist", err)
	}

	for i := range bl {
		b := bl[i]

		parseChan := periodicHostsUpdate(b)

		if i == len(bl)-1 {
			// last blocklist

			dnsserver.GetConfig(c).
				AddPlugin(func(next plugin.Handler) plugin.Handler {
					b.Next = next
					return b
				})
		} else {
			nextBlocklist := bl[i+1]

			dnsserver.GetConfig(c).
				AddPlugin(func(next plugin.Handler) plugin.Handler {
					b.Next = nextBlocklist
					return b
				})
		}

		c.OnStartup(func() error {
			b.readBlocklist()
			return nil
		})

		c.OnShutdown(func() error {
			close(parseChan)
			return nil
	  })
	}

	return nil
}

func getBlockResponseCode(blockResponse string) (int, error) {
	switch blockResponse {
	case "nxdomain":
		return dns.RcodeNameError, nil
	case "refused":
		return dns.RcodeRefused, nil
	default:
		return 0, fmt.Errorf("unknown response code '%s', must be either 'nxdomain' or 'refused'", blockResponse)
	}
}

func parseBlocklist(c *caddy.Controller) ([]*Blocklist, error) {
	bl := []*Blocklist{}

	for c.Next() {
		b, err := parseStanza(c)
		if err != nil {
			return nil, err
		}
		bl = append(bl, b)
	}

	return bl, nil
}

func checkFileorURL(file string, rootdir string) (string, error) {
	_, err := url.ParseRequestURI(file)
	if err == nil {
		return file, nil
	}

	if !filepath.IsAbs(file) && rootdir != "" {
		file = filepath.Join(rootdir, file)
	}
	s, err := os.Stat(file)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("unable to access hosts file '%s': %v", file, err)
		}
		log.Warningf("File does not exist: %s", file)
	}
	if s != nil && s.IsDir() {
		log.Warningf("Hosts file %q is a directory", file)
	}

	return file, nil
}

func parseStanza(c *caddy.Controller) (*Blocklist, error) {
	b := New()
	config := dnsserver.GetConfig(c)

	if !c.Args(&b.blocklistLocation) {
		return b, c.ArgErr()
	}

	// check blocklist location
	filename, err := checkFileorURL(b.blocklistLocation, config.Root)
	if err != nil {
		return b, err
	}

	b.blocklistLocation = filename

	for c.NextBlock() {
		option := c.Val()
		switch option {
		case "allowlist":
			remaining := c.RemainingArgs()
			if len(remaining) != 1 {
				return b, fmt.Errorf("allowlist requires a single argument.")
			}

			b.allowlistLocation = remaining[0]
			// check if file or url and check reachability
			b.allowlistLocation, err = checkFileorURL(b.allowlistLocation, config.Root)
			if err != nil {
				return b, err
			}

			log.Debugf("Setting allowlist location to %s", b.allowlistLocation)
		case "domain_metrics":
			b.domainMetrics = true
		case "bootstrap_dns":
			b.bootStrapDNS = c.RemainingArgs()[0]
		case "block_response":
			remaining := c.RemainingArgs()
			if len(remaining) != 1 {
				return b, fmt.Errorf("block_response requires a single argument.")
			}

			blockResponseCode, err := getBlockResponseCode(remaining[0])
			if err != nil {
				return b, err
			}
			b.blockResponse = blockResponseCode
		case "reload":
			remaining := c.RemainingArgs()
			if len(remaining) != 1 {
				return b, c.Errf("reload needs a duration (zero seconds to disable)")
			}
			reload, err := time.ParseDuration(remaining[0])
			if err != nil {
				return b, c.Errf("invalid duration for reload '%s'", remaining[0])
			}
			if reload < 0 {
				return b, c.Errf("invalid negative duration for reload '%s'", remaining[0])
			}
			b.reload = reload
		default:
			return b, fmt.Errorf("unexpected '%v' command", option)
		}
	}

	if c.NextArg() {
		return b, fmt.Errorf("To many arguments for blocklist.")
	}

	return b, nil
}
