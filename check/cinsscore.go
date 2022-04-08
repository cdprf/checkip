package check

import (
	"bufio"
	"fmt"
	"net"
	"os"

	"github.com/jreisinger/checkip"
)

type cins struct {
	BadGuyIP bool
	CountIPs int
}

// CinsScore searches ipaddr in https://cinsscore.com/list/ci-badguys.txt.
func CinsScore(ipaddr net.IP) (checkip.Result, error) {
	result := checkip.Result{
		Name: "cinsscore.com",
		Type: checkip.TypeSec,
		Info: checkip.EmptyInfo{},
	}

	file := "/var/tmp/cins.txt"
	url := "http://cinsscore.com/list/ci-badguys.txt"

	if err := checkip.UpdateFile(file, url, ""); err != nil {
		return result, checkip.NewError(err)
	}

	cins, err := cinsSearch(ipaddr, file)
	if err != nil {
		return result, checkip.NewError(fmt.Errorf("searching %s in %s: %v", ipaddr, file, err))
	}

	result.Malicious = cins.BadGuyIP

	return result, nil
}

// search searches the ippadrr in filename fills in ET data.
func cinsSearch(ipaddr net.IP, filename string) (cins, error) {
	file, err := os.Open(filename)
	if err != nil {
		return cins{}, err
	}

	var cinsArmy cins
	s := bufio.NewScanner(file)
	for s.Scan() {
		line := s.Text()
		cinsArmy.CountIPs++
		if line == ipaddr.String() {
			cinsArmy.BadGuyIP = true
		}
	}
	if s.Err() != nil {
		return cins{}, err
	}
	return cinsArmy, nil
}