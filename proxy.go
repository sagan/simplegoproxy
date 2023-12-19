package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/sagan/simplegoproxy/util"
)

const (
	PREFIX        = "_sgp_"
	HEADER_PREFIX = "header_"
)

func proxyFunc(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("get: path=%s, query=%s\n", r.URL.Path, r.URL.RawQuery)
	url := r.URL.Path
	if r.URL.RawQuery != "" {
		url += "?" + r.URL.RawQuery
	}
	if !util.IsUrl(url) {
		url = "https://" + url
	}
	response, err := FetchUrl(url)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf("Failed to fetch url: %v", err)))
		return
	}
	defer response.Body.Close()
	w.WriteHeader(response.StatusCode)
	for name, headers := range response.Header {
		for _, header := range headers {
			w.Header().Add(name, header)
		}
	}
	io.Copy(w, response.Body)
}

func FetchUrl(urlStr string) (*http.Response, error) {
	urlObj, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url %s : %v", urlStr, err)
	}
	urlQuery := urlObj.Query()
	headers := map[string]string{}
	for key, values := range urlQuery {
		if !strings.HasPrefix(key, PREFIX) {
			continue
		}
		urlQuery.Del(key)
		key = key[len(PREFIX):]
		value := values[0]
		if strings.HasPrefix(key, HEADER_PREFIX) {
			header := key[len(HEADER_PREFIX):]
			if header != "" {
				headers[header] = value
			}
		}
	}
	urlObj.RawQuery = urlQuery.Encode()
	urlStr = urlObj.String()
	fmt.Printf("access: %s, headers=%v\n", urlStr, headers)
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return http.DefaultClient.Do(req)
}
