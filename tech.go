package wappalyzer

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/gookit/color"
	"github.com/twmb/murmur3"
	"github.com/yearnming/ehole/module/queue"
	"github.com/yinheli/mahonia"
	"golang.org/x/net/html/charset"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	wappalyzer1 "github.com/projectdiscovery/wappalyzergo"
)

type FinScan struct {
	UrlQueue    *queue.Queue
	Ch          chan []string
	Wg          sync.WaitGroup
	Thread      int
	Output      string
	Proxy       string
	AllResult   []Outrestul
	FocusResult []Outrestul
	Finpx       *Packjson
}

type Outrestul struct {
	Url        string `json:"url"`
	Cms        string `json:"cms"`
	Server     string `json:"server"`
	Statuscode int    `json:"statuscode"`
	Length     int    `json:"length"`
	Title      string `json:"title"`
}

//type Packjson struct {
//	Fingerprint []Fingerprint
//}
//
//type Fingerprint struct {
//	Cms      string
//	Method   string
//	Location string
//	Keyword  []string
//}

type resps struct {
	url        string
	body       string
	header     map[string][]string
	server     string
	statuscode int
	length     int
	title      string
	//jsurl      []string
	favhash string
}

// 得将ehole得指纹识别更改接受的接口和返回值

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

func (s *FinScan) FingerScan(resp *http.Response, url string) {
	err := LoadWebfingerprint("D:\\Go\\ehole\\finger.json")
	if err != nil {
		color.RGBStyleFromString("237,64,35").Println("[error] fingerprint file error!!!")
		os.Exit(1)
	}
	var data *resps
	data, err = httprequest(resp, url)
	if err != nil {
		log.Fatal(err)
	}

	headers := MapToJson(data.header)
	var cms []string
	for _, finp := range s.Finpx.Fingerprint {
		if finp.Location == "body" {
			if finp.Method == "keyword" {
				if iskeyword(data.body, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "faviconhash" {
				if data.favhash == finp.Keyword[0] {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(data.body, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
		if finp.Location == "header" {
			if finp.Method == "keyword" {
				if iskeyword(headers, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(headers, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
		if finp.Location == "title" {
			if finp.Method == "keyword" {
				if iskeyword(data.title, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(data.title, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
	}
	cms = RemoveDuplicatesAndEmpty(cms)
	cmss := strings.Join(cms, ",")
	out := Outrestul{data.url, cmss, data.server, data.statuscode, data.length, data.title}
	s.AllResult = append(s.AllResult, out)
	if len(out.Cms) != 0 {
		outstr := fmt.Sprintf("[ %s | %s | %s | %d | %d | %s ]", out.Url, out.Cms, out.Server, out.Statuscode, out.Length, out.Title)
		color.RGBStyleFromString("237,64,35").Println(outstr)
		s.FocusResult = append(s.FocusResult, out)
	} else {
		outstr := fmt.Sprintf("[ %s | %s | %s | %d | %d | %s ]", out.Url, out.Cms, out.Server, out.Statuscode, out.Length, out.Title)
		fmt.Println(outstr)
	}
}

func httprequest(resp *http.Response, url string) (*resps, error) {
	result, _ := ioutil.ReadAll(resp.Body)
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	httpbody := string(result)
	httpbody = toUtf8(httpbody, contentType)
	title := gettitle(httpbody)
	httpheader := resp.Header
	var server string
	capital, ok := httpheader["Server"]
	if ok {
		server = capital[0]
	} else {
		Powered, ok := httpheader["X-Powered-By"]
		if ok {
			server = Powered[0]
		} else {
			server = "None"
		}
	}
	//var jsurl []string
	//if url1[1] == "0" {
	//	jsurl = Jsjump(httpbody, url1[0])
	//} else {
	//	jsurl = []string{""}
	//}
	favhash := getfavicon(httpbody, url)
	s := resps{url, httpbody, resp.Header, server, resp.StatusCode, len(httpbody), title, favhash}
	return &s, nil
	//return map[string]struct{}{}
}

func toUtf8(content string, contentType string) string {
	var htmlEncode string
	var htmlEncode2 string
	var htmlEncode3 string
	htmlEncode = "gb18030"
	if strings.Contains(contentType, "gbk") || strings.Contains(contentType, "gb2312") || strings.Contains(contentType, "gb18030") || strings.Contains(contentType, "windows-1252") {
		htmlEncode = "gb18030"
	} else if strings.Contains(contentType, "big5") {
		htmlEncode = "big5"
	} else if strings.Contains(contentType, "utf-8") {
		//实际上，这里获取的编码未必是正确的，在下面还要做比对
		htmlEncode = "utf-8"
	}

	reg := regexp.MustCompile(`(?is)<meta[^>]*charset\s*=["']?\s*([A-Za-z0-9\-]+)`)
	match := reg.FindStringSubmatch(content)
	if len(match) > 1 {
		contentType = strings.ToLower(match[1])
		if strings.Contains(contentType, "gbk") || strings.Contains(contentType, "gb2312") || strings.Contains(contentType, "gb18030") || strings.Contains(contentType, "windows-1252") {
			htmlEncode2 = "gb18030"
		} else if strings.Contains(contentType, "big5") {
			htmlEncode2 = "big5"
		} else if strings.Contains(contentType, "utf-8") {
			htmlEncode2 = "utf-8"
		}
	}

	reg = regexp.MustCompile(`(?is)<title[^>]*>(.*?)<\/title>`)
	match = reg.FindStringSubmatch(content)
	if len(match) > 1 {
		aa := match[1]
		_, contentType, _ = charset.DetermineEncoding([]byte(aa), "")
		contentType = strings.ToLower(contentType)
		if strings.Contains(contentType, "gbk") || strings.Contains(contentType, "gb2312") || strings.Contains(contentType, "gb18030") || strings.Contains(contentType, "windows-1252") {
			htmlEncode3 = "gb18030"
		} else if strings.Contains(contentType, "big5") {
			htmlEncode3 = "big5"
		} else if strings.Contains(contentType, "utf-8") {
			htmlEncode3 = "utf-8"
		}
	}

	if htmlEncode != "" && htmlEncode2 != "" && htmlEncode != htmlEncode2 {
		htmlEncode = htmlEncode2
	}
	if htmlEncode == "utf-8" && htmlEncode != htmlEncode3 {
		htmlEncode = htmlEncode3
	}

	if htmlEncode != "" && htmlEncode != "utf-8" {
		content = Convert(content, htmlEncode, "utf-8")
	}

	return content
}

/**
 * 编码转换
 * 需要传入原始编码和输出编码，如果原始编码传入出错，则转换出来的文本会乱码
 */
func Convert(src string, srcCode string, tagCode string) string {
	if srcCode == tagCode {
		return src
	}
	srcCoder := mahonia.NewDecoder(srcCode)
	srcResult := srcCoder.ConvertString(src)
	tagCoder := mahonia.NewDecoder(tagCode)
	_, cdata, _ := tagCoder.Translate([]byte(srcResult), true)
	result := string(cdata)
	return result
}

// 获取网页标题
func gettitle(httpbody string) string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(httpbody))
	if err != nil {
		return "Not found"
	}
	title := doc.Find("title").Text()
	title = strings.Replace(title, "\n", "", -1)
	title = strings.Trim(title, " ")
	return title
}

func getfavicon(httpbody string, turl string) string {
	faviconpaths := xegexpjs(`href="(.*?favicon....)"`, httpbody)
	var faviconpath string
	u, err := url.Parse(turl)
	if err != nil {
		panic(err)
	}
	turl = u.Scheme + "://" + u.Host
	if len(faviconpaths) > 0 {
		fav := faviconpaths[0][1]
		if fav[:2] == "//" {
			faviconpath = "http:" + fav
		} else {
			if fav[:4] == "http" {
				faviconpath = fav
			} else {
				faviconpath = turl + "/" + fav
			}

		}
	} else {
		faviconpath = turl + "/favicon.ico"
	}
	return favicohash(faviconpath)
}

func xegexpjs(reg string, resp string) (reslut1 [][]string) {
	reg1 := regexp.MustCompile(reg)
	if reg1 == nil {
		log.Println("regexp err")
		return nil
	}
	result1 := reg1.FindAllStringSubmatch(resp, -1)
	return result1
}

func favicohash(host string) string {
	timeout := time.Duration(8 * time.Second)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse /* 不进入重定向 */
		},
	}
	resp, err := client.Get(host)
	if err != nil {
		//log.Println("favicon client error:", err)
		return "0"
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			//log.Println("favicon file read error: ", err)
			return "0"
		}
		return Mmh3Hash32(StandBase64(body))
	} else {
		return "0"
	}
}

func StandBase64(braw []byte) []byte {
	bckd := base64.StdEncoding.EncodeToString(braw)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()

}

func Mmh3Hash32(raw []byte) string {
	var h32 hash.Hash32 = murmur3.New32()
	_, err := h32.Write([]byte(raw))
	if err == nil {
		return fmt.Sprintf("%d", int32(h32.Sum32()))
	} else {
		//log.Println("favicon Mmh3Hash32 error:", err)
		return "0"
	}
}

func MapToJson(param map[string][]string) string {
	dataType, _ := json.Marshal(param)
	dataString := string(dataType)
	return dataString
}

func iskeyword(str string, keyword []string) bool {
	var x bool
	x = true
	for _, k := range keyword {
		if strings.Contains(str, k) {
			x = x && true
		} else {
			x = x && false
		}
	}
	return x
}

func isregular(str string, keyword []string) bool {
	var x bool
	x = true
	for _, k := range keyword {
		re := regexp.MustCompile(k)
		if re.Match([]byte(str)) {
			x = x && true
		} else {
			x = x && false
		}
	}
	return x
}

func RemoveDuplicatesAndEmpty(a []string) (ret []string) {
	a_len := len(a)
	for i := 0; i < a_len; i++ {
		if (i > 0 && a[i-1] == a[i]) || len(a[i]) == 0 {
			continue
		}
		ret = append(ret, a[i])
	}
	return
}
