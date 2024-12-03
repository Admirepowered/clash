package geodata

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Dreamacro/clash/log"
)

func createTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "",
	}
}

func found(domain string) string {
	domainList := map[string]string{
		"steamcommunity.com":            "2.16.174.204",
		"github.com":                    "140.82.116.3",
		"objects.githubusercontent.com": "185.199.108.133",
	}

	if ip, ok := domainList[domain]; ok {
		return ip
	}
	return ""
}

func makeRequest(url string, method string, data string, headers map[string]string) (string, error) {
	hostname := strings.Split(strings.Split(url, "//")[1], "/")[0]
	ip := found(hostname)
	if ip == "" {
		ips, err := net.LookupIP(hostname)
		if err != nil {
			return "", fmt.Errorf("无法解析域名: %s", hostname)
		}
		ip = ips[0].String()
	}

	requestURL := strings.Replace(url, hostname, ip, 1)
	tr := &http.Transport{
		TLSClientConfig: createTLSConfig(),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, net.JoinHostPort(ip, "443"))
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   1800 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if headers == nil {
		headers = make(map[string]string)
	}
	headers["Host"] = hostname
	var req *http.Request
	var err error
	if method == "POST" {
		req, err = http.NewRequest("POST", requestURL, strings.NewReader(data))
	} else {
		req, err = http.NewRequest("GET", requestURL, nil)
	}
	if err != nil {
		return "", err
	}
	req.Host = hostname
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求错误: %s", err)
	}
	Location := resp.Header.Get("Location")
	if Location != "" {
		log.Infoln("Rediecting to Location:%s", Location)
		return makeRequest(Location, method, data, headers)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应错误: %s", err)
	}
	return string(body), nil
}
