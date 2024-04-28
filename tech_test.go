package wappalyzer

import (
	"fmt"
	"github.com/gookit/color"
	"github.com/yearnming/ehole/module/queue"
	"log"
	"net/http"
	"testing"
)

func TestFingerScan(t *testing.T) {
	url := "http://39.103.172.110/"
	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	//data, _ := io.ReadAll(resp.Body) // 例如，忽略错误

	s := &FinScan{
		UrlQueue:    queue.NewQueue(),
		AllResult:   []Outrestul{},
		FocusResult: []Outrestul{},
	}
	s.FingerScan(resp, url)
	color.RGBStyleFromString("244,211,49").Println("\n重点资产：")
	for _, aas := range s.FocusResult {
		fmt.Printf(fmt.Sprintf("[ %s | ", aas.Url))
		color.RGBStyleFromString("237,64,35").Printf(fmt.Sprintf("%s", aas.Cms))
		fmt.Printf(fmt.Sprintf(" | %s | %d | %d | %s ]\n", aas.Server, aas.Statuscode, aas.Length, aas.Title))
	}
	if s.Output != "" {
		outfile(s.Output, s.AllResult)
	}
}
