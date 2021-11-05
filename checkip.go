// Checkip checks an IP address using various public services. An IP address is
// checked by running one or more Checkers. There are two kinds of Checkers. An
// InfoChecker just gathers some useful information about the IP address. A
// SecChecker says whether the IP address is considered malicious or not.
package checkip

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"

	"github.com/logrusorgru/aurora"
)

// Checker runs a check of an IP address. It also returns its name.
type Checker interface {
	Check(ip net.IP) error
	Name() string
}

// InfoChecker finds information about an IP address.
type InfoChecker interface {
	Info() string
	Checker
}

// SecChecker checks an IP address from the security point of view.
type SecChecker interface {
	IsMalicious() bool
	Checker
}

// Run runs checkers concurrently checking the ipaddr.
func Run(checkers []Checker, ipaddr net.IP) []Result {
	var res []Result

	var wg sync.WaitGroup
	for _, chk := range checkers {
		wg.Add(1)
		go func(c Checker) {
			defer wg.Done()
			err := c.Check(ipaddr)
			switch v := c.(type) {
			case InfoChecker:
				r := Result{Name: v.Name(), Type: "Info", Data: v, Info: v.Info(), Err: err}
				res = append(res, r)
			case SecChecker:
				r := Result{Name: c.Name(), Type: "Sec", Data: v, IsMalicious: v.IsMalicious(), Err: err}
				res = append(res, r)
			}

		}(chk)
	}
	wg.Wait()

	return res
}

// func redactSecrets(s string) string {
// 	key := regexp.MustCompile(`(key|pass|password)=\w+`)
// 	return key.ReplaceAllString(s, "${1}=REDACTED")
// }

// Result holds the result of a check.
type Result struct {
	Name        string
	Type        string
	Data        Checker
	Info        string
	IsMalicious bool
	Err         error
}

type byName []Result

func (x byName) Len() int           { return len(x) }
func (x byName) Less(i, j int) bool { return x[i].Name < x[j].Name }
func (x byName) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }

// Print prints condensed results to stdout.
func Print(results []Result) error {
	sort.Sort(byName(results))

	var malicious, total float64
	for _, r := range results {
		if r.Type == "Info" {
			fmt.Printf("%-15s %s\n", r.Name, r.Info)
			continue
		}
		if r.IsMalicious {
			malicious++
		}
		total++
	}
	probabilityMalicious := malicious / total

	var msg string
	switch {
	case probabilityMalicious < 0.15:
		msg = fmt.Sprint(aurora.Green("Malicious"))
	case probabilityMalicious < 0.50:
		msg = fmt.Sprint(aurora.Yellow("Malicious"))
	default:
		msg = fmt.Sprint(aurora.Red("Malicious"))
	}

	_, err := fmt.Printf("%s\t%.0f%%\n", msg, probabilityMalicious*100)
	return err
}

// PrintJSON prints all data from results in JSON format to stdout.
func PrintJSON(results []Result) error {
	sort.Sort(byName(results))

	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(&results)
}
