package wappalyzer

import (
	"fmt"
	"github.com/gookit/color"
	"github.com/yearnming/ehole/module/queue"
	"io"
	"log"
	"net/http"
	"sync"
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

	thread := 100
	s := &FinScan{
		UrlQueue: queue.NewQueue(),
		Ch:       make(chan []string, thread),
		Wg:       sync.WaitGroup{},
		Thread:   thread,
	}
	//fmt.Printf("[ url 为: %v ]\n", url)
	s.FingerScan(resp.Header, data, url)
	color.RGBStyleFromString("244,211,49").Println("\n重点资产：")
	color.RGBStyleFromString("237,64,35").Printf(fmt.Sprintf("[ %s ]\n", s.FocusResult.Cms))

	fingerprints := Wappalyzer(resp.Header, data, url)
	fmt.Printf("[ wappalyzer: %v ]\n", fingerprints)

}
