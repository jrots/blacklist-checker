package blacklistchecker

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)


type BlacklistChecker interface {
	Check(ip string) ([]string, error)

}

type queueItem struct {
	IP        net.IP
	ReverseIP string
	Blacklist string
	Error     error
	FQDN      string
	Response  []string
}

type blacklistCommand struct {
	queueSize  int
	results []queueItem

	// channels
	queue    chan queueItem
	response chan queueItem

	blacklisted []string

	wg sync.WaitGroup
}

type blacklistChecker struct {
	verbose    bool
	version    string
	nameServer string
	hosts   []string

}

func NewBlackListChecker() BlacklistChecker {
	return &blacklistChecker{
		verbose: false,
		hosts: GetBlacklistHosts(),
		nameServer: "8.8.8.8:53",
	}
}

func (b *blacklistChecker) Check(ip string) ([]string, error) {
	ipAddress := net.ParseIP(ip)
	ips := []net.IP{ipAddress}

	command := &blacklistCommand{
		queue: make(chan queueItem, len(b.hosts)),
		response: make(chan queueItem),
	}
	command.wg.Add(len(ips) * len(b.hosts))

	if b.verbose {
		fmt.Printf("checking ip %s\n", ip)
	}
	go b.processQueue(command)

	if b.verbose {
		fmt.Printf("done processing queue\n")
	}
	go b.addQueueItemsToQueue(command, ips)
	if b.verbose {
		fmt.Printf("done adding items to queue\n")
	}
	command.wg.Wait()

	return command.blacklisted, nil
}

func (b *blacklistChecker) processQueue(command *blacklistCommand) {
	for {
		select {
		case qi := <-command.queue:
			if b.verbose {
				fmt.Printf("%s adding %s\n", qi.IP,  qi.Blacklist)
			}
			go b.checkIfBlacklisted(command.response, command, qi.IP, qi.Blacklist)
		case qr := <-command.response:
			if len(qr.Response) > 0 {
				command.blacklisted = append(command.blacklisted,fmt.Sprintf("%s blacklisted on %s with %s", qr.IP.String(), qr.Blacklist, strings.Join(qr.Response, ",")))
			}
		}
	}
}

func (b *blacklistChecker) addQueueItemsToQueue(command *blacklistCommand, IPs []net.IP) {

	for _, ip := range IPs {
		for _, blacklist := range b.hosts {
			if b.verbose {
				fmt.Printf("adding  %s %s\n",ip.String(), blacklist)
			}

			command.queue <- queueItem{
				IP:        ip,
				Blacklist: blacklist,
			}
		}
	}

}


/*IP net.IP, blacklist string

 */
func (b *blacklistChecker) checkIfBlacklisted(channel chan<- queueItem, command *blacklistCommand, IP net.IP, blacklist string) {

	defer command.wg.Done()

	client := &dns.Client{Timeout:400 * time.Millisecond}

	qi := queueItem{
		IP:        IP,
		ReverseIP: ReverseIP(IP.String()),
		Blacklist: blacklist,
		FQDN:      fmt.Sprintf("%s.%s.", ReverseIP(IP.String()), blacklist),
	}

	if b.verbose {
		fmt.Printf("Checking %s\n", qi.FQDN)
	}

	m := new(dns.Msg)
	m.SetQuestion(qi.FQDN, dns.TypeA)
	m.RecursionDesired = true

	r, _, err := client.Exchange(m, b.nameServer)
	if err != nil {
		if b.verbose {
			fmt.Printf("Failed to query: %v for %v on %v with query %v\n", err, qi.IP, qi.Blacklist, qi.FQDN)
		}
		qi.Error = err
		command.wg.Add(1)
		command.queue <- queueItem{
			IP:        IP,
			Blacklist: blacklist,
		}
		return
	}

	if r.Rcode != dns.RcodeSuccess {
		qi.Error = errors.New(fmt.Sprintf("Recieved Rcode: %v is different from %v (RcodeSuccess) for %v", r.Rcode, dns.RcodeSuccess, qi.FQDN))
		if b.verbose {
			fmt.Printf("%v\n", qi.Error)
		}
		return
	}

	var resp []string

	for _, a := range r.Answer {
		if rsp, ok := a.(*dns.A); ok {
			resp = append(resp, rsp.A.String())
		}
	}

	qi.Response = resp

	if b.verbose {
		fmt.Printf("Successfully queried %v with %v response\n", qi.FQDN, qi.Response)
	}

	channel <- qi

}
