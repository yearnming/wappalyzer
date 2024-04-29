package wappalyzer

import (
	"encoding/json"
	"io/ioutil"
)

type Packjson struct {
	Fingerprint []Fingerprint
}

type Fingerprint struct {
	Cms      string
	Method   string
	Location string
	Keyword  []string
}

var (
	Webfingerprint *Packjson
)

// LoadWebfingerprint 加载内置指纹库
func LoadWebfingerprint(path string) error {
	//data, err := ioutil.ReadFile(path)
	//if err != nil {
	//	//log.Fatal("文件错误")
	//	return err
	//}
	data := []byte(path)
	var config Packjson
	err := json.Unmarshal(data, &config)
	if err != nil {
		return err
	}
	Webfingerprint = &config
	return nil
}

// LoadWebfingerprint1 加载指定指纹库
func LoadWebfingerprint1(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		//log.Fatal("文件错误")
		return err
	}
	//data := []byte(path)
	var config Packjson
	err = json.Unmarshal(data, &config)
	if err != nil {
		return err
	}
	Webfingerprint = &config
	return nil
}

func GetWebfingerprint() *Packjson {
	return Webfingerprint
}
