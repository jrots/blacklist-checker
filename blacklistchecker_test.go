package blacklistchecker

import (
	"testing"
)
func TestBlackList(t *testing.T){

	/*
	app.HelpFlag.Short('h')
	command = kingpin.MustParse(app.Parse(os.Args[1:]))

	queue = make(chan QueueItem, *queueSize)
	response = make(chan QueueItem)

	hosts = GetBlacklistHosts()
	*/
	blacklist := NewBlackListChecker();
	blacklist.Check("103.113.3.170")

	result := "Hello"
	if result != "Hello" {
		t.Errorf("hello, expected %v got %v", "hello dude",result)
	}
	/*
	func main() {
		switch command {
		case "list":
			for _, blacklist := range hosts {
				fmt.Printf("%s\n", blacklist)
			}
		case "cidr":
			ips, err := Hosts(*rangeCidr)
			if err != nil {
				fmt.Printf("%v", err)
				return
			}
			wg.Add(len(ips) * len(hosts))
			go ProcessQueue()
			go AddQueueItemsToQueue(ips)
			wg.Wait()
		case "ip":
			ips := []net.IP{*ip}
			wg.Add(len(ips) * len(hosts))
			go ProcessQueue()
			go AddQueueItemsToQueue(ips)
			wg.Wait()
		}
	}
*/
	}
