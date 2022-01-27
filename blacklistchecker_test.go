package blacklistchecker

import (
	"fmt"
	"testing"
)
func TestBlackList(t *testing.T){

	blacklist := NewBlackListChecker()
	ip := "103.113.3.170"
	ret, _ := blacklist.Check(ip)

	if len(ret) == 0 {
		t.Errorf("excpected blacklisted for ip %v got %v", ip ,ret)
	} else {
		fmt.Printf("%v", ret)
	}
	ip = "77.73.176.113"
	ret, _ = blacklist.Check(ip)

	if len(ret) > 0 {
		t.Errorf("excpected not blacklisted for ip %v got %v", ip ,ret)
	}
}
