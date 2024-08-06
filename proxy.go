package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/vincent-petithory/dataurl"

	"github.com/sagan/simplegoproxy/util"
)

const (
	HEADER_PREFIX          = "header_"
	RESPONSE_HEADER_PREFIX = "resheader_"
	SUB_PREFIX             = "sub_"
	CORS_STRING            = "cors"
	NOCACHE_STRING         = "nocache"
	NORF_STRING            = "norf"
	PROXY_STRING           = "proxy"
	IMPERSONATE_STRING     = "impersonate"
	FORCESUB_STRING        = "forcesub"
	NOCSP_STRING           = "nocsp"
	TIMEOUT_STRING         = "timeout"
	INSECURE_STRING        = "insecure"
	COOKIE_STRING          = "cookie"
	BASICAUTH_STRING       = "basicauth"
	FDHEADERS_STRING       = "fdheaders"
	BODY_STRING            = "body"
	TYPE_STRING            = "type"
	METHOD_STRING          = "method"
	REFERER_STRING         = "referer"
	SCOPE_STRING           = "scope"
	SIGN_STRING            = "sign"
)

var (
	TEXTUAL_MIMES = []string{
		"application/json",
		"application/xml",
		"application/atom+xml",
		"application/x-sh",
	}
)

func sendError(w http.ResponseWriter, msg string, args ...any) {
	w.WriteHeader(500)
	w.Write([]byte(fmt.Sprintf(msg, args...)))
}

func proxyFunc(w http.ResponseWriter, r *http.Request, prefix string, key string) {
	defer r.Body.Close()
	targetUrl := r.URL.EscapedPath()
	var modparams url.Values
	// accept "_sgp_a=1/https://ipcfg.io/json" style request url
	if strings.HasPrefix(targetUrl, prefix) {
		index := strings.Index(targetUrl, "/")
		if index == -1 {
			sendError(w, "Invalid url")
			return
		}
		modparamsStr := targetUrl[:index]
		targetUrl = targetUrl[index+1:]
		var err error
		modparams, err = url.ParseQuery(modparamsStr)
		if err != nil {
			sendError(w, "Failed to parse modparams %s: %v", modparamsStr, err)
			return
		}
	}
	targetUrlObj, err := url.Parse(targetUrl)
	if err != nil {
		sendError(w, "Failed to parse url %s: %v", targetUrl, err)
		return
	}
	if targetUrlObj.Scheme == "" {
		targetUrlObj.Scheme = "https"
	}
	queryParams := url.Values{}
	if targetUrlObj.Scheme != "data" {
		if targetUrlObj.Host != "" && targetUrlObj.Path == "" {
			targetUrlObj.Path = "/"
		}
		targetUrlQuery := targetUrlObj.Query()
		for key, values := range r.URL.Query() {
			if strings.HasPrefix(key, prefix) && len(key) > len(prefix) {
				queryParams[key[len(prefix):]] = values
			} else {
				targetUrlQuery[key] = values
			}
		}
		targetUrlObj.RawQuery = targetUrlQuery.Encode()
	}
	for key, values := range modparams {
		if !strings.HasPrefix(key, prefix) || len(key) <= len(prefix) {
			sendError(w, "Invalid modparam %q", key)
			return
		}
		queryParams[key[len(prefix):]] = values
	}
	response, err := FetchUrl(targetUrlObj, r, queryParams, prefix, key)
	if err != nil {
		sendError(w, "Failed to fetch url: %v", err)
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

func FetchUrl(urlObj *url.URL, srReq *http.Request, queryParams url.Values,
	prefix, signkey string) (*http.Response, error) {
	headers := map[string]string{}
	responseHeaders := map[string]string{}
	subs := map[string]string{}
	cors := false
	insecure := false
	forcesub := false
	nocsp := false
	nocache := false
	norf := false // no redirect following
	proxy := ""
	impersonate := ""
	timeout := 0
	cookie := ""
	basicauth := ""
	fdheaders := ""
	body := ""
	contentType := ""
	method := http.MethodGet
	sign := ""
	var scopes []string
	var referers []string
	for key, values := range queryParams {
		value := values[0]
		if signkey != "" {
			value = applySecrets(value)
		}
		switch key {
		case CORS_STRING:
			cors = true
		case INSECURE_STRING:
			insecure = true
		case FORCESUB_STRING:
			forcesub = true
		case NOCSP_STRING:
			nocsp = true
		case NORF_STRING:
			norf = true
		case NOCACHE_STRING:
			nocache = true
		case PROXY_STRING:
			proxy = value
		case IMPERSONATE_STRING:
			impersonate = value
		case COOKIE_STRING:
			cookie = value
		case BASICAUTH_STRING:
			basicauth = value
		case METHOD_STRING:
			method = strings.ToUpper(value)
		case FDHEADERS_STRING:
			fdheaders = value
		case BODY_STRING:
			body = value
		case TYPE_STRING:
			contentType = value
		case SCOPE_STRING:
			for _, value := range values {
				if value != "" {
					scopes = append(scopes, value)
				}
			}
		case REFERER_STRING:
			referers = append(referers, values...)
		case SIGN_STRING:
			sign = value
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
						headers[strings.ToLower(h)] = value
					}
				} else if strings.HasPrefix(key, RESPONSE_HEADER_PREFIX) {
					h := key[len(RESPONSE_HEADER_PREFIX):]
					if h != "" {
						responseHeaders[strings.ToLower(h)] = value
					}
				} else if strings.HasPrefix(key, SUB_PREFIX) {
					h := key[len(SUB_PREFIX):]
					if h != "" {
						subs[h] = value
					}
				} else {
					return nil, fmt.Errorf("invalid (non-existent) modification parameter '%s'", key)
				}
			}
		}
	}
	if len(referers) > 0 {
		actualReferer := srReq.Header.Get("Referer")
		match := false
		if actualReferer == "" {
			match = slices.Index(referers, "") != -1
		} else {
			for _, referer := range referers {
				if referer != "" && util.MatchUrlPattern(referer, actualReferer) {
					match = true
					break
				}
			}
		}
		if !match {
			return nil, fmt.Errorf("invalid referer '%s', allowed referers: %v", actualReferer, referers)
		}
	}

	if urlObj.Scheme != "data" {
		if signkey != "" {
			signUrlQuery := urlObj.Query()
			for key, values := range queryParams {
				if key != SIGN_STRING {
					signUrlQuery[prefix+key] = values
				}
			}
			urlObj.RawQuery = signUrlQuery.Encode()
			signUrl := urlObj.String()
			if sign == "" {
				return nil, fmt.Errorf(`sign is required but not found`)
			}
			if len(scopes) > 0 {
				targetUrlQuery := url.Values{}
				for key, values := range signUrlQuery {
					if !strings.HasPrefix(key, prefix) {
						signUrlQuery.Del(key)
						targetUrlQuery[key] = values
					}
				}
				urlObj.RawQuery = targetUrlQuery.Encode()
				signUrl = "?" + signUrlQuery.Encode()
				targetUrl := urlObj.String()
				matchScopes := false
				for _, scope := range scopes {
					if util.MatchUrlPattern(scope, targetUrl) {
						matchScopes = true
						break
					}
				}
				if !matchScopes {
					return nil, fmt.Errorf(`invalid url %s for scopes %v`, targetUrl, scopes)
				}
			}
			messageMAC, err := hex.DecodeString(sign)
			if err != nil {
				return nil, fmt.Errorf(`invalid sign hex string "%s": %v`, sign, err)
			}
			mac := hmac.New(sha256.New, []byte(signkey))
			mac.Write([]byte(signUrl))
			expectedMAC := mac.Sum(nil)
			if !hmac.Equal(messageMAC, expectedMAC) {
				return nil, fmt.Errorf(`invalid sign "%s" for url "%s"`, sign, signUrl)
			}
		}
		if urlObj.User != nil {
			basicauth = urlObj.User.String()
			urlObj.User = nil
		}
		if cookie != "" {
			headers["cookie"] = cookie
		}
		if basicauth != "" {
			headers["authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(basicauth))
		}
		if contentType != "" {
			headers["content-type"] = contentType
		}
		if headers["content-type"] == "" && method == http.MethodPost && body != "" {
			headers["content-type"] = "application/x-www-form-urlencoded"
		}
		forwardHeaders := []string{"Authorization", "If-Match", "If-Modified-Since", "If-None-Match", "If-Range",
			"If-Unmodified-Since", "Range"}
		if fdheaders != "" {
			if fdheaders == "*" {
				for h := range srReq.Header {
					forwardHeaders = append(forwardHeaders, h)
				}
			} else if fdheaders == "\n" {
				forwardHeaders = nil
			} else {
				forwardHeaders = append(forwardHeaders, strings.Split(fdheaders, ",")...)
			}
		}
		for _, h := range forwardHeaders {
			h = strings.ToLower(h)
			if _, ok := headers[h]; ok {
				continue
			}
			if v := srReq.Header.Get(h); v != "" {
				headers[h] = v
			}
		}

		if signkey != "" {
			// only do secret substitution if request signing is enabled
			urlQuery := urlObj.Query()
			for key, values := range urlQuery {
				for i := range values {
					values[i] = applySecrets(values[i])
				}
				urlQuery[key] = values
			}
			urlObj.RawQuery = urlQuery.Encode()
		}
	}

	urlStr := urlObj.String()
	log.Printf("Fetch: url=%s, params=%v", urlStr, queryParams)
	var res *http.Response
	if urlObj.Scheme == "data" {
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URLs
		dataURL, err := dataurl.DecodeString(urlStr)
		if err != nil {
			return nil, fmt.Errorf("invalid data url: %v", err)
		}
		contentType := dataURL.ContentType()
		res = &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{contentType},
			},
			Body: io.NopCloser(bytes.NewReader(dataURL.Data)),
		}
	} else {
		var reqBody io.Reader
		if body != "" {
			reqBody = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, urlStr, reqBody)
		if err != nil {
			return nil, fmt.Errorf("invalid http request: %v", err)
		}
		res, err = util.FetchUrl(req, impersonate, insecure, timeout, proxy, norf, headers)
		if err != nil {
			return res, err
		}
	}

	res.Header.Del("Strict-Transport-Security")
	res.Header.Del("Clear-Site-Data")
	res.Header.Del("Set-Cookie")
	res.Header.Set("Referrer-Policy", "no-referrer")
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
	if nocache {
		res.Header.Set("Cache-Control", "no-store")
		res.Header.Set("Expires", "0")
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
				if mime != "" && (strings.HasPrefix(mime, "text/") || slices.Index(TEXTUAL_MIMES, mime) != -1) {
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
	return res, nil
}

var secretRegexp = regexp.MustCompile("__SECRET_[_a-zA-Z][_a-zA-Z0-9]*?__")

// replace all  __SECRET_ABC__ style substrings with SECRET_ABC env value.
func applySecrets(str string) string {
	return secretRegexp.ReplaceAllStringFunc(str, func(s string) string {
		env := s[2 : len(s)-2]
		if variable, ok := os.LookupEnv(env); ok {
			return variable
		}
		return s
	})
}
