package util

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/Noooste/azuretls-client"
)

type impersonateProfile struct {
	// "chrome", "firefox", "opera", "safari", "edge", "ios", "android"
	navigator     string
	ja3           string
	h2fingerpring string
	headers       [][]string // use "\n" as placeholder for order; use "" (empty) to delete a header
}

const (
	HTTP_HEADER_PLACEHOLDER = "\n"
)

var (
	// all supported impersonate names
	Impersonates []string
)

func init() {
	for key := range impersonateProfiles {
		Impersonates = append(Impersonates, key)
	}
	slices.Sort(Impersonates)
}

var impersonateProfiles = map[string]*impersonateProfile{
	"chrome120": {
		navigator:     "chrome",
		ja3:           "772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-45-11-65037-18-5-51-0-23-27-43-16-10-35-17513-13,29-23-24,0",
		h2fingerpring: "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p",
		headers: [][]string{
			{"Cache-Control", "max-age=0"},
			{"Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`},
			{"Sec-Ch-Ua-Mobile", `?0`},
			{"Sec-Ch-Ua-Platform", `"Windows"`},
			{"Upgrade-Insecure-Requests", "1"},
			{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
			{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"Sec-Fetch-Site", `none`},
			{"Sec-Fetch-Mode", `navigate`},
			{"Sec-Fetch-User", `?1`},
			{"Sec-Fetch-Dest", `document`},
			// {"Accept-Encoding", "gzip, deflate, br"},
			{"Accept-Language", "en-US,en;q=0.9"},
			{"Cookie", HTTP_HEADER_PLACEHOLDER},
		},
	},
}

func FetchUrl(urlStr string, impersonate string, insecure bool, timeout int, proxy string,
	headers map[string]string) (*http.Response, error) {
	if impersonate == "" {
		req, err := http.NewRequest("GET", urlStr, nil)
		if err != nil {
			return nil, err
		}
		for key, value := range headers {
			if value != "" {
				req.Header.Set(key, value)
			} else {
				req.Header.Del(key)
			}
		}
		var httpClient *http.Client
		if insecure || proxy != "" || timeout > 0 {
			httpClient = &http.Client{
				Timeout: time.Duration(timeout) * time.Second,
			}
			if insecure || proxy != "" {
				var proxyFunc func(*http.Request) (*url.URL, error)
				if proxy != "" {
					proxyUrl, err := url.Parse(proxy)
					if err != nil {
						return nil, fmt.Errorf("failed to parse proxy %s: %v", proxy, err)
					}
					proxyFunc = http.ProxyURL(proxyUrl)
				}
				httpClient.Transport = &http.Transport{
					Proxy:           proxyFunc,
					TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
				}
			}
		} else {
			httpClient = http.DefaultClient
		}
		return httpClient.Do(req)
	}
	ip := impersonateProfiles[impersonate]
	if ip == nil {
		return nil, fmt.Errorf("impersonate target %s not supported", impersonate)
	}
	session := azuretls.NewSession()
	session.SetTimeout(time.Duration(timeout) * time.Second)
	if ip.ja3 != "" {
		if err := session.ApplyJa3(ip.ja3, ip.navigator); err != nil {
			return nil, fmt.Errorf("failed to set ja3: %v", err)
		}
	}
	if ip.h2fingerpring != "" {
		if err := session.ApplyHTTP2(ip.h2fingerpring); err != nil {
			return nil, fmt.Errorf("failed to set h2 finterprint: %v", err)
		}
	}
	if proxy != "" {
		if err := session.SetProxy(proxy); err != nil {
			return nil, fmt.Errorf("failed to set proxy: %v", err)
		}
	}
	if insecure {
		session.InsecureSkipVerify = true
	}

	allHeaders := [][]string{}
	effectHeaders := [][]string{}
	headerIndexs := map[string]int{}
	allHeaders = append(allHeaders, ip.headers...)
	for key, value := range headers {
		allHeaders = append(allHeaders, []string{key, value})
	}
	for _, header := range allHeaders {
		if index, ok := headerIndexs[header[0]]; ok {
			effectHeaders[index] = []string{header[0], header[1]}
			if header[1] == "" {
				delete(headerIndexs, header[0])
			}
		} else if header[1] != "" {
			effectHeaders = append(effectHeaders, []string{header[0], header[1]})
			headerIndexs[header[0]] = len(headers) - 1
		}
	}
	orderedHeaders := azuretls.OrderedHeaders{}
	for _, header := range effectHeaders {
		if header[1] == "" || header[1] == HTTP_HEADER_PLACEHOLDER {
			continue
		}
		orderedHeaders = append(orderedHeaders, header)
	}

	res, err := session.Get(urlStr, orderedHeaders)
	if err != nil {
		if _, ok := err.(net.Error); ok {
			return nil, fmt.Errorf("failed to fetch url: <network error>: %v", err)
		}
		return nil, fmt.Errorf("failed to fetch url: %v", err)
	}
	return &http.Response{
		StatusCode: res.StatusCode,
		Header:     http.Header(res.Header),
		Body:       io.NopCloser(bytes.NewReader(res.Body)),
	}, nil
}
