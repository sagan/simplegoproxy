package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/sagan/simplegoproxy/util"
)

const (
	HEADER_PREFIX          = "header_"
	RESPONSE_HEADER_PREFIX = "resheader_"
	SUB_PREFIX             = "sub_"
	CORS_STRING            = "cors"
	PROXY_STRING           = "proxy"
	IMPERSONATE_STRING     = "impersonate"
	FORCESUB_STRING        = "forcesub"
	NOCSP_STRING           = "nocsp"
	TIMEOUT_STRING         = "timeout"
	INSECURE_STRING        = "insecure"
	COOKIE_STRING          = "cookie"
	BASICAUTH_STRING       = "basicauth"
)

var (
	TEXT_MIMES = []string{"text/html", "application/json", "text/json", "text/plain", "text/csv"}
)

func proxyFunc(w http.ResponseWriter, r *http.Request, prefix string) {
	defer r.Body.Close()
	targetUrl := r.URL.Path
	modparams := ""
	// accept "_sgp_a=1/https://ipcfg.io/json" style request url
	if strings.HasPrefix(targetUrl, prefix) {
		index := strings.Index(targetUrl, "/")
		if index == -1 {
			w.WriteHeader(400)
			w.Write([]byte("Invalid url"))
			return
		}
		modparams = targetUrl[:index]
		targetUrl = targetUrl[index+1:]
	}
	targetUrlObj, err := url.Parse(targetUrl)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte(fmt.Sprintf("Failed to parse url %s: %v", targetUrl, err)))
		return
	}
	if targetUrlObj.Scheme == "" {
		targetUrlObj.Scheme = "https"
	}
	if targetUrlObj.Host != "" && targetUrlObj.Path == "" {
		targetUrlObj.Path = "/"
	}
	targetUrlObj.RawQuery = r.URL.RawQuery
	if targetUrlObj.RawQuery != "" && modparams != "" {
		targetUrlObj.RawQuery += "&"
	}
	targetUrlObj.RawQuery += modparams
	response, err := FetchUrl(targetUrlObj, r, prefix)
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

func FetchUrl(urlObj *url.URL, srReq *http.Request, prefix string) (*http.Response, error) {
	urlQuery := urlObj.Query()
	headers := map[string]string{}
	responseHeaders := map[string]string{}
	subs := map[string]string{}
	cors := false
	insecure := false
	forcesub := false
	nocsp := false
	proxy := ""
	impersonate := ""
	timeout := 0
	cookie := ""
	basicauth := ""
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
		case IMPERSONATE_STRING:
			impersonate = value
		case COOKIE_STRING:
			cookie = value
		case BASICAUTH_STRING:
			basicauth = value
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
	if urlObj.User != nil {
		basicauth = urlObj.User.String()
		urlObj.User = nil
	}
	if cookie != "" {
		headers["Cookie"] = cookie
	}
	if basicauth != "" {
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(basicauth))
	}
	urlObj.RawQuery = urlQuery.Encode()
	urlStr := urlObj.String()
	log.Printf("Fetch: url=%s", urlStr)
	res, err := util.FetchUrl(urlStr, impersonate, insecure, timeout, proxy, headers)
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
