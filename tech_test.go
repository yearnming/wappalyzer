package wappalyzer

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"testing"
)

func TestFingerScan(t *testing.T) {

	//output := ""
	//proxy := ""
	url := "http://113.31.155.8"
	//url := "http://39.103.172.110/"
	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body) // 例如，忽略错误

	fingerprints := Wappalyzer(resp.Header, data, url)
	fmt.Printf("[ wappalyzer: %v ]\n", fingerprints)

}
