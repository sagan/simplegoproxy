package util

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Noooste/azuretls-client"
)

type ImpersonateProfile struct {
	// "chrome", "firefox", "opera", "safari", "edge", "ios", "android"
	Navigator     string
	Ja3           string
	H2fingerpring string
	Headers       [][]string // use "\n" as placeholder for order; use "" (empty) to delete a header
	Comment       string
}

const (
	HTTP_HEADER_PLACEHOLDER = "\n"
)

var (
	// all supported impersonate names
	Impersonates []string
)

func init() {
	for key := range ImpersonateProfiles {
		Impersonates = append(Impersonates, key)
	}
	slices.Sort(Impersonates)
}

var ImpersonateProfiles = map[string]*ImpersonateProfile{
	"chrome120": {
		Navigator:     "chrome",
		Comment:       "Chrome 120 on Windows 11 x64 en-US",
		Ja3:           "772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-45-11-65037-18-5-51-0-23-27-43-16-10-35-17513-13,29-23-24,0",
		H2fingerpring: "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p",
		Headers: [][]string{
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
	"firefox121": {
		Navigator: "firefox",
		Comment:   "Firefox 121 on Windows 11 x64 en-US",
		// Ja3:           "772,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0",
		// utls do not support TLS 34 delegated_credentials (34) (IANA) extension at this time.
		// see https://github.com/refraction-networking/utls/issues/274
		Ja3:           "772,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-51-43-13-45-28-65037,29-23-24-25-256-257,0",
		H2fingerpring: "1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
		Headers: [][]string{
			{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"},
			{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
			{"Accept-Language", "en-US,en;q=0.5"},
			{"Accept-Encoding", "gzip, deflate, br"},
			{"Cookie", HTTP_HEADER_PLACEHOLDER},
			{"Upgrade-Insecure-Requests", "1"},
			{"Sec-Fetch-Dest", `document`},
			{"Sec-Fetch-Mode", `navigate`},
			{"Sec-Fetch-Site", `none`},
			{"Sec-Fetch-User", `?1`},
			{"te", "trailers"},
		},
	},
}

func FetchUrl(req *http.Request, impersonate string, insecure bool, timeout int, proxy string, norf bool,
	headers map[string]string) (*http.Response, error) {
	reqUrl := req.URL.String()
	if impersonate == "" {
		for key, value := range headers {
			if value != "" {
				req.Header.Set(key, value)
			} else {
				req.Header.Del(key)
			}
		}
		var httpClient *http.Client
		if insecure || norf || proxy != "" || timeout > 0 {
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
				} else {
					proxyFunc = http.ProxyFromEnvironment
				}
				httpClient.Transport = &http.Transport{
					Proxy:           proxyFunc,
					TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
				}
			}
			if norf {
				httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				}
			}
		} else {
			httpClient = http.DefaultClient
		}
		return httpClient.Do(req)
	}
	ip := ImpersonateProfiles[impersonate]
	if ip == nil {
		return nil, fmt.Errorf("impersonate target %s not supported", impersonate)
	}
	session := azuretls.NewSession()
	session.SetTimeout(time.Duration(timeout) * time.Second)
	if ip.Ja3 != "" {
		if err := session.ApplyJa3(ip.Ja3, ip.Navigator); err != nil {
			return nil, fmt.Errorf("failed to set ja3: %v", err)
		}
	}
	if ip.H2fingerpring != "" {
		if err := session.ApplyHTTP2(ip.H2fingerpring); err != nil {
			return nil, fmt.Errorf("failed to set h2 finterprint: %v", err)
		}
	}
	if proxy == "" {
		proxy = ParseProxyFromEnv(reqUrl)
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
	effectiveHeaders := [][]string{}
	headerIndexs := map[string]int{}
	allHeaders = append(allHeaders, ip.Headers...)
	for key, value := range headers {
		allHeaders = append(allHeaders, []string{key, value})
	}
	for _, header := range allHeaders {
		headerLowerCase := strings.ToLower(header[0])
		if index, ok := headerIndexs[headerLowerCase]; ok {
			effectiveHeaders[index] = []string{header[0], header[1]}
			if header[1] == "" {
				delete(headerIndexs, headerLowerCase)
			}
		} else if header[1] != "" {
			effectiveHeaders = append(effectiveHeaders, []string{header[0], header[1]})
			headerIndexs[headerLowerCase] = len(effectiveHeaders) - 1
		}
	}
	orderedHeaders := azuretls.OrderedHeaders{}
	for _, header := range effectiveHeaders {
		if header[1] == "" || header[1] == HTTP_HEADER_PLACEHOLDER {
			continue
		}
		orderedHeaders = append(orderedHeaders, header)
	}

	res, err := session.Do(&azuretls.Request{
		Method:           req.Method,
		Url:              reqUrl,
		IgnoreBody:       true,
		DisableRedirects: norf,
	}, orderedHeaders)
	if err != nil {
		if _, ok := err.(net.Error); ok {
			return nil, fmt.Errorf("failed to fetch url: <network error>: %v", err)
		}
		return nil, fmt.Errorf("failed to fetch url: %v", err)
	}
	return &http.Response{
		StatusCode: res.StatusCode,
		Header:     http.Header(res.Header),
		Body:       res.RawBody,
	}, nil
}

// Parse standard HTTP_PROXY, HTTPS_PROXY, NO_PROXY (and lowercase versions) envs, return proxy for urlStr.
func ParseProxyFromEnv(urlStr string) string {
	if urlStr == "" {
		return ""
	}
	urlObj, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	proxyUrl, err := http.ProxyFromEnvironment(&http.Request{URL: urlObj})
	if err != nil || proxyUrl == nil {
		return ""
	}
	return proxyUrl.String()
}

func getUrlPatternParts(pattern string) map[string]string {
	if pattern == "<all_urls>" {
		return map[string]string{
			"scheme": "*",
			"host":   "*",
			"path":   "*",
		}
	}
	matchScheme := `(\*|http|https|file|ftp)`
	matchHost := `(\*|(?:\*\.)?(?:[^/*]+))?`
	matchPath := `(.*)?`
	regex := regexp.MustCompile("^" + matchScheme + "://" + matchHost + "(/)" + matchPath + "$")
	result := regex.FindStringSubmatch(pattern)
	if result == nil {
		return nil
	}
	return map[string]string{
		"scheme": result[1],
		"host":   result[2],
		"path":   result[4],
	}
}

// Create a Chrome extension match pattern style matcher, that test a url against the pattern.
// Mattern syntax: https://developer.chrome.com/docs/extensions/develop/concepts/match-patterns .
// Pattern examples: https://*/ , https://*/foo* , https://*.google.com/foo*bar .
// Adapted from https://github.com/nickclaw/url-match-patterns
func CreateUrlPatternMatcher(pattern string) func(string) bool {
	parts := getUrlPatternParts(pattern)
	if parts == nil {
		return func(_ string) bool { return false }
	}
	str := "^"
	if parts["scheme"] == "*" {
		str += "(http|https)"
	} else {
		str += parts["scheme"]
	}
	str += "://"
	if parts["host"] == "*" {
		str += ".*"
	} else if len(parts["host"]) >= 2 && parts["host"][:2] == "*." {
		str += `.*`
		str += `\.`
		str += regexp.QuoteMeta(parts["host"][2:])
	} else if parts["host"] != "" {
		str += parts["host"]
	}
	if parts["path"] == "" {
		str += "/.*"
	} else if parts["path"] != "" {
		str += "/"
		str += regexp.MustCompile(`\\\*`).ReplaceAllString(regexp.QuoteMeta(parts["path"]), ".*")
	}
	str += "$"
	// fmt.Printf("actual pattern: %s\n", str)
	regex := regexp.MustCompile(str)
	return func(url string) bool {
		return regex.MatchString(url)
	}
}

func MatchUrlPattern(pattern string, optionalUrl string) bool {
	matcher := CreateUrlPatternMatcher(pattern)
	return matcher(optionalUrl)
}
