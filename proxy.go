package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sagan/simplegoproxy/util"
)

const (
	HEADER_PREFIX          = "header_"
	RESPONSE_HEADER_PREFIX = "resheader_"
	SUB_PREFIX             = "sub_"
	CORS_STRING            = "cors"
	PROXY_STRING           = "proxy"
	FORCESUB_STRING        = "forcesub"
	NOCSP_STRING           = "nocsp"
	TIMEOUT_STRING         = "timeout"
	INSECURE_STRING        = "insecure"
)

var (
	TEXT_MIMES = []string{"text/html", "application/json", "text/json", "text/plain", "text/csv"}
)

func proxyFunc(w http.ResponseWriter, r *http.Request, prefix string) {
	defer r.Body.Close()
	log.Printf("Access: path=%s, query=%s", r.URL.Path, r.URL.RawQuery)
	url := r.URL.Path
	if r.URL.RawQuery != "" {
		url += "?" + r.URL.RawQuery
	}
	if !util.IsUrl(url) {
		url = "https://" + url
	}
	response, err := FetchUrl(url, r, prefix)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf("Failed to fetch url: %v", err)))
		return
	}
	defer response.Body.Close()
	for name, headers := range response.Header {
		for _, header := range headers {
			w.Header().Add(name, header)
		}
	}
	w.WriteHeader(response.StatusCode)
	io.Copy(w, response.Body)
}

func FetchUrl(urlStr string, srReq *http.Request, prefix string) (*http.Response, error) {
	urlObj, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url %s : %v", urlStr, err)
	}
	urlQuery := urlObj.Query()
	headers := map[string]string{}
	responseHeaders := map[string]string{}
	subs := map[string]string{}
	cors := false
	insecure := false
	forcesub := false
	nocsp := false
	proxy := ""
	timeout := 0
	for key, values := range urlQuery {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		urlQuery.Del(key)
		key = key[len(prefix):]
		value := values[0]
		switch key {
		case CORS_STRING:
			cors = true
		case INSECURE_STRING:
			insecure = true
		case FORCESUB_STRING:
			forcesub = true
		case NOCSP_STRING:
			nocsp = true
		case PROXY_STRING:
			proxy = value
		case TIMEOUT_STRING:
			if t, err := strconv.Atoi(value); err != nil {
				return nil, fmt.Errorf("failed to parse timtout %s: %v", value, err)
			} else {
				timeout = t
			}
		default:
			{
				if strings.HasPrefix(key, HEADER_PREFIX) {
					h := key[len(HEADER_PREFIX):]
					if h != "" {
						headers[h] = value
					}
				} else if strings.HasPrefix(key, RESPONSE_HEADER_PREFIX) {
					h := key[len(RESPONSE_HEADER_PREFIX):]
					if h != "" {
						responseHeaders[h] = value
					}
				} else if strings.HasPrefix(key, SUB_PREFIX) {
					h := key[len(SUB_PREFIX):]
					if h != "" {
						subs[h] = value
					}
				}
			}
		}
	}
	urlObj.RawQuery = urlQuery.Encode()
	urlStr = urlObj.String()
	log.Printf("Fetch: url=%s, headers=%v", urlStr, headers)
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
	res, err := httpClient.Do(req)
	if err != nil {
		return res, err
	}
	res.Header.Del("Strict-Transport-Security")
	if cors {
		res.Header.Set("Access-Control-Allow-Origin", "*")
		res.Header.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		res.Header.Set("Access-Control-Allow-Credentials", "true")
		if h := srReq.Header.Get("Access-Control-Request-Headers"); h != "" {
			res.Header.Set("Access-Control-Allow-Headers", h)
		}
		res.Header.Set("Vary", "Access-Control-Request-Headers")
	}
	if nocsp {
		res.Header.Del("Content-Security-Policy")
		res.Header.Del("X-Content-Type-Options")
		res.Header.Del("X-Frame-Options")
	}
	for key, value := range responseHeaders {
		if value != "" {
			res.Header.Set(key, value)
		} else {
			res.Header.Del(key)
		}
	}
	if len(subs) > 0 {
		doSub := forcesub
		if !doSub {
			if contentType := res.Header.Get("Content-Type"); contentType != "" {
				mime, _, _ := mime.ParseMediaType(contentType)
				if mime != "" && slices.Index(TEXT_MIMES, mime) != -1 {
					doSub = true
				}
			}
		}
		if doSub {
			body, err := io.ReadAll(res.Body)
			if err != nil {
				res.StatusCode = 500
				res.Body = io.NopCloser(strings.NewReader(fmt.Sprintf("Failed to read body: %v", err)))
			} else {
				data := string(body) // for now, assume UTF-8
				for sub, replace := range subs {
					data = strings.ReplaceAll(data, sub, replace)
				}
				res.Body = io.NopCloser(strings.NewReader(data))
			}
		}
	}
	return res, err
}
