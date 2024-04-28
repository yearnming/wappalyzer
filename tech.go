package wappalyzer

import (
	"fmt"
	"io"
	"log"
	"net/http"

	wappalyzer1 "github.com/projectdiscovery/wappalyzergo"
)

func New() {
	resp, err := http.DefaultClient.Get("http://39.103.172.110/")
	if err != nil {
		log.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body) // 例如，忽略错误

	wappalyzerClient, err := wappalyzer1.New()
	if err != nil {
		log.Fatal(err)
	}
	fingerprints := wappalyzerClient.Fingerprint(resp.Header, data)
	fmt.Printf("%v\n", fingerprints)
	// Output: map[Acquia Cloud Platform:{} Amazon EC2:{} Apache:{} Cloudflare:{} Drupal:{} PHP:{} Percona:{} React:{} Varnish:{}]

	fingerprintsWithCats := wappalyzerClient.FingerprintWithCats(resp.Header, data)
	fmt.Printf("%v\n", fingerprintsWithCats)
}
