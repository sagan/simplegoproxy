package proxy

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	htmlTemplate "html/template"
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
	"text/template"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/vincent-petithory/dataurl"
	"gopkg.in/yaml.v2"

	"github.com/sagan/simplegoproxy/constants"
	"github.com/sagan/simplegoproxy/flags"
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
	USER_STRING            = "user"
	FDHEADERS_STRING       = "fdheaders"
	BODY_STRING            = "body"
	RESBODY_STRING         = "resbody"
	RESBODYTYPE_STRING     = "resbodytype"
	TYPE_STRING            = "type"
	RESTYPE_STRING         = "restype"
	METHOD_STRING          = "method"
	REFERER_STRING         = "referer"
	ORIGIN_STRING          = "origin"
	SCOPE_STRING           = "scope"
	SIGN_STRING            = "sign"
	KEYTYPE_STRING         = "keytype"
	VALIDBEFORE_STRING     = "validbefore"
	VALIDAFTER_STRING      = "validafter"
	RESPASS_STRING         = "respass"
	DEBUG_STRING           = "debug"
	ARG_SRING              = "arg"
	ARGS_SRING             = "args"
)

type Template interface {
	Execute(wr io.Writer, data any) error
}

var (
	TEXTUAL_MIMES = []string{
		"application/json",
		"application/xml",
		"application/atom+xml",
		"application/x-sh",
	}
)

func sendError(w http.ResponseWriter, r *http.Request, supress, dolog bool, msg string, args ...any) {
	errormsg := fmt.Sprintf(msg, args...)
	if supress {
		http.NotFound(w, r)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(errormsg))
	}
	if dolog {
		log.Print(errormsg)
	}
}

func ProxyFunc(w http.ResponseWriter, r *http.Request, prefix, key string, keytypeBlacklist, openScopes []string,
	supressError, doLog bool, enableUnix, enableFile, enableRclone, enableCurl, enableExec bool,
	rcloneBinary, rcloneConfig, curlBinary string, cipher cipher.AEAD) {
	defer r.Body.Close()
	reqUrlQuery := r.URL.Query()
	targetUrl := r.URL.EscapedPath()
	encryptUrlMode := false
	if constants.EncryptedUrlRegex.MatchString(targetUrl) {
		decrypted, err := util.Decrypt(cipher, targetUrl)
		if err != nil {
			sendError(w, r, supressError, doLog, "Invalid encrypted url: %v", err)
			return
		}
		targetUrl = string(decrypted)
		targetUrlObj, err := url.Parse(targetUrl)
		if err != nil {
			sendError(w, r, supressError, doLog, "Invalid decrypted target url: %v", err)
			return
		}
		reqUrlQuery = targetUrlObj.Query()
		targetUrlObj.RawQuery = ""
		targetUrl = targetUrlObj.String()
		encryptUrlMode = true
	}

	var modparams url.Values
	// accept "_sgp_a=1/https://ipcfg.io/json" style request url
	if !encryptUrlMode && strings.HasPrefix(targetUrl, prefix) {
		index := strings.Index(targetUrl, "/")
		if index == -1 {
			sendError(w, r, supressError, doLog, "Invalid url")
			return
		}
		modparamsStr := targetUrl[:index]
		targetUrl = targetUrl[index+1:]
		var err error
		modparams, err = url.ParseQuery(modparamsStr)
		if err != nil {
			sendError(w, r, supressError, doLog, "Failed to parse modparams %s: %v", modparamsStr, err)
			return
		}
	}
	targetUrlObj, err := url.Parse(targetUrl)
	if err != nil {
		sendError(w, r, supressError, doLog, "Failed to parse url %s: %v", targetUrl, err)
		return
	}
	if targetUrlObj.Scheme == "" {
		targetUrlObj.Scheme = "https"
	}
	queryParams := url.Values{}
	if targetUrlObj.Host != "" && targetUrlObj.Path == "" {
		targetUrlObj.Path = "/"
	}
	targetUrlQuery := targetUrlObj.Query()
	for key, values := range reqUrlQuery {
		if strings.HasPrefix(key, prefix) && len(key) > len(prefix) {
			queryParams[key[len(prefix):]] = values
		} else if targetUrlObj.Scheme != "data" {
			targetUrlQuery[key] = values
		}
	}
	targetUrlObj.RawQuery = targetUrlQuery.Encode()
	for key, values := range modparams {
		if !strings.HasPrefix(key, prefix) || len(key) <= len(prefix) {
			sendError(w, r, supressError, doLog, "Invalid modparam %q", key)
			return
		}
		queryParams[key[len(prefix):]] = values
	}
	if doLog {
		log.Printf("Fetch: url=%s, params=%v, src=%s", targetUrlObj, queryParams, r.RemoteAddr)
	}
	if strings.HasPrefix(targetUrlObj.Scheme, "curl+") && len(targetUrlObj.Scheme) > 5 {
		if !enableCurl {
			sendError(w, r, supressError, doLog, "curl url is not enabled")
			return
		}
	} else {
		switch targetUrlObj.Scheme {
		case "unix":
			if !enableUnix {
				sendError(w, r, supressError, doLog, "unix domain socket is not enabled")
				return
			}
		case "file":
			if !enableFile {
				sendError(w, r, supressError, doLog, "file url is not enabled")
				return
			}
		case "rclone":
			if !enableRclone {
				sendError(w, r, supressError, doLog, "rclone url is not enabled")
				return
			}
		case "exec":
			if !enableExec {
				sendError(w, r, supressError, doLog, "exec url is not enabled")
				return
			}
		case "http", "https", "data":
			if queryParams.Has(RESPASS_STRING) && !encryptUrlMode {
				sendError(w, r, supressError, doLog, "url with respass must be accessed via encrypted url")
				return
			}
		default:
			sendError(w, r, supressError, doLog, "unsupported url scheme %q", targetUrlObj.Scheme)
			return
		}
	}
	response, err := FetchUrl(targetUrlObj, r, queryParams, prefix, key,
		keytypeBlacklist, openScopes, rcloneBinary, rcloneConfig, doLog)
	if err != nil {
		sendError(w, r, supressError, doLog, "Failed to fetch url: %v", err)
		return
	}
	if response.Body != nil {
		defer response.Body.Close()
	}
	for name, headers := range response.Header {
		for _, header := range headers {
			w.Header().Add(name, header)
		}
	}
	w.WriteHeader(response.StatusCode)
	if response.Body != nil {
		io.Copy(w, response.Body)
	}
}

func FetchUrl(urlObj *url.URL, srReq *http.Request, queryParams url.Values, prefix, signkey string,
	keytypeBlacklist, openScopes []string, rcloneBinary, rcloneConfig string, doLog bool) (*http.Response, error) {
	var err error
	header := http.Header{}
	responseHeaders := map[string]string{}
	subs := map[string]string{}
	cors := false
	insecure := false
	forcesub := false
	nocsp := false
	nocache := false
	norf := false // no redirect following
	debug := false
	// current url does not require (enforce) signing, but will disable env secret if not signed
	openMode := util.MatchUrlPatterns(openScopes, urlObj.String(), false)
	proxy := ""
	impersonate := ""
	timeout := int64(0)
	cookie := ""
	user := ""
	fdheaders := ""
	body := ""
	forwardBody := false
	templateContents := ""
	var resBodyTemplate Template
	contentType := ""
	responseContentType := ""
	responseBodyType := ""
	method := http.MethodGet
	keytype := ""
	sign := ""
	// password to encrypt final response body to client
	var respass = ""
	var scopes []string
	var referers []string
	var origines []string
	now := time.Now().Unix()
	for key, values := range queryParams {
		value := values[0]
		if signkey != "" && !openMode && urlObj.Scheme != "data" {
			value = applySecrets(value)
		}
		switch key {
		case ARG_SRING, ARGS_SRING:
			// do nothing
		case DEBUG_STRING:
			debug = true
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
		case RESPASS_STRING:
			respass = value
			if respass != "" && signkey == "" {
				return nil, fmt.Errorf("respass can only be used when request signing is enabled")
			}
		case IMPERSONATE_STRING:
			impersonate = value
		case COOKIE_STRING:
			cookie = value
		case USER_STRING:
			user = value
		case METHOD_STRING:
			method = strings.ToUpper(value)
		case FDHEADERS_STRING:
			fdheaders = value
		case BODY_STRING:
			body = value
		case RESBODY_STRING:
			templateContents = value
		case TYPE_STRING:
			contentType = value
		case RESTYPE_STRING:
			responseContentType = value
		case RESBODYTYPE_STRING:
			responseBodyType = value
		case KEYTYPE_STRING:
			keytype = value
		case SCOPE_STRING:
			for _, value := range values {
				if value != "" {
					scopes = append(scopes, value)
				}
			}
		case REFERER_STRING:
			referers = append(referers, values...)
		case ORIGIN_STRING:
			origines = append(origines, values...)
		case VALIDBEFORE_STRING:
			if validbefore, err := util.ParseLocalDateTime(value); err != nil {
				return nil, fmt.Errorf("invalid validbefore: %v", err)
			} else if now > validbefore {
				return nil, fmt.Errorf("url expired")
			}
		case VALIDAFTER_STRING:
			if validafter, err := util.ParseLocalDateTime(value); err != nil {
				return nil, fmt.Errorf("invalid validafter: %v", err)
			} else if now < validafter {
				return nil, fmt.Errorf("url doesn't take effect yet")
			}
		case SIGN_STRING:
			sign = value
		case TIMEOUT_STRING:
			if t, err := strconv.ParseInt(value, 10, 64); err != nil {
				return nil, fmt.Errorf("failed to parse timtout %s: %v", value, err)
			} else if t == -1 {
				timeout = constants.INFINITE_TIMEOUT
			} else if t < 0 {
				return nil, fmt.Errorf("netagive timeout is invalid (except -1, which means infinite)")
			} else {
				timeout = t
			}
		default:
			{
				if strings.HasPrefix(key, HEADER_PREFIX) {
					h := key[len(HEADER_PREFIX):]
					if h != "" {
						header.Add(h, value)
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
	if len(referers) > 0 && !util.MatchUrlPatterns(referers, srReq.Header.Get("Referer"), true) {
		return nil, fmt.Errorf("invalid referer '%s', allowed referers: %v", srReq.Header.Get("Referer"), referers)
	}
	if len(origines) > 0 && !util.MatchUrlPatterns(origines, srReq.Header.Get("Origin"), true) {
		return nil, fmt.Errorf("invalid origin '%s', allowed origines: %v", srReq.Header.Get("Origin"), origines)
	}
	if templateContents != "" {
		if responseContentType == "" || responseContentType == "html" {
			resBodyTemplate, err = htmlTemplate.New("template").Parse(templateContents)
		} else {
			resBodyTemplate, err = template.New("template").Parse(templateContents)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid template: %v", err)
		}
	}

	if urlObj.Scheme != "data" {
		if signkey != "" {
			signUrlQuery := urlObj.Query()
			for key, values := range queryParams {
				if key != SIGN_STRING && key != KEYTYPE_STRING {
					signUrlQuery[prefix+key] = values
				}
			}
			urlObj.RawQuery = signUrlQuery.Encode()
			signUrl := urlObj.String()
			if sign != "" {
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
					if targetUrl := urlObj.String(); !util.MatchUrlPatterns(scopes, targetUrl, false) {
						return nil, fmt.Errorf(`invalid url %s for scopes %v`, targetUrl, scopes)
					}
				}
				if keytype != "" {
					if slices.Contains(keytypeBlacklist, keytype) {
						return nil, fmt.Errorf("keytype %q is revoked", keytype)
					}
				}
				messageMAC, err := hex.DecodeString(sign)
				if err != nil {
					return nil, fmt.Errorf(`invalid sign hex string "%s": %v`, sign, err)
				}
				mac := hmac.New(sha256.New, []byte(Realkey(signkey, keytype)))
				mac.Write([]byte(signUrl))
				expectedMAC := mac.Sum(nil)
				if !hmac.Equal(messageMAC, expectedMAC) {
					return nil, fmt.Errorf(`invalid sign "%s" for url "%s"`, sign, signUrl)
				}
			} else if !openMode {
				return nil, fmt.Errorf(`sign is required but not found`)
			}
		}
		if urlObj.User != nil {
			user = urlObj.User.String()
			urlObj.User = nil
		}
		if cookie != "" {
			header.Set("Cookie", cookie)
		}
		if user != "" {
			header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user)))
		}
		if contentType != "" {
			header.Set("Content-Type", util.Mime(contentType))
		}
		forwardHeaders := []string{"If-Match", "If-Modified-Since", "If-None-Match", "If-Range",
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
			// http2 pseudo header style
			if strings.HasPrefix(h, ":") {
				switch h {
				case ":method":
					method = srReq.Method
				case ":body":
					forwardBody = true
				default:
					return nil, fmt.Errorf("invalid fdheader %q", h)
				}
			} else {
				if len(header.Values(h)) > 0 || len(srReq.Header.Values(h)) == 0 {
					continue
				}
				header[h] = srReq.Header[h]
			}
		}
		if header.Get("Content-Type") == "" && method == http.MethodPost && body != "" {
			header.Set("Content-Type", "application/x-www-form-urlencoded")
		}

		if signkey != "" && !openMode && urlObj.Scheme != "data" {
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

	var req *http.Request
	urlStr := urlObj.String()
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
		if forwardBody && srReq.Body != nil {
			reqBody = srReq.Body
		} else if body != "" {
			reqBody = strings.NewReader(body)
		}
		req, err = http.NewRequestWithContext(srReq.Context(), method, urlStr, reqBody)
		if err != nil {
			return nil, fmt.Errorf("invalid http request: %v", err)
		}
		req.Header = header
		username, password, _ := strings.Cut(user, ":")
		res, err = util.FetchUrl(&util.NetRequest{
			Req:          req,
			Impersonate:  impersonate,
			Insecure:     insecure,
			Timeout:      timeout,
			Proxy:        proxy,
			Norf:         norf,
			RcloneBinary: rcloneBinary,
			RcloneConfig: rcloneConfig,
			Debug:        debug,
			Username:     username,
			Password:     password,
			DoLog:        doLog,
			Params:       queryParams,
		})
		if err != nil {
			return res, err
		}
	}

	originalResponseContentType := res.Header.Get("Content-Type")
	res.Header.Del("Strict-Transport-Security")
	res.Header.Del("Clear-Site-Data")
	res.Header.Del("Set-Cookie")
	res.Header.Set("Referrer-Policy", "no-referrer")
	if cors {
		res.Header.Set("Access-Control-Allow-Origin", "*")
		res.Header.Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		// res.Header.Set("Access-Control-Allow-Credentials", "true") // it's security vulerable as sgp has admin API now.
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
	if responseContentType != "" {
		res.Header.Set("Content-Type", util.Mime(responseContentType))
	}

	if resBodyTemplate != nil {
		var request = map[string]any{}
		if req != nil {
			request["method"] = req.Method
			request["header"] = req.Header
		} else {
			request["method"] = http.MethodGet
			request["header"] = http.Header{}
		}
		var response = map[string]any{
			"status": res.StatusCode,
			"header": res.Header,
		}
		if responseBodyType == "" && originalResponseContentType != "" {
			if ct, _, err := mime.ParseMediaType(originalResponseContentType); err == nil {
				responseBodyType = ct
			}
		}
		var body []byte
		if res.Body != nil {
			body, err = io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				return util.ErrResponseMsg("Failed to read body: %v", err), nil
			}
		}
		var data any
		var dataerr error
		if body != nil {
			switch responseBodyType {
			case "application/json", "text/json", "json":
				dataerr = json.Unmarshal(body, &data)
			case "application/yaml", "text/yaml", "yaml":
				dataerr = yaml.Unmarshal(body, &data)
			case "application/xml", "text/xml", "xml":
				dataerr = xml.Unmarshal(body, &data)
			case "application/toml", "text/toml", "toml":
				dataerr = toml.Unmarshal(body, &data)
			}
		}
		response["body"] = string(body)
		response["data"] = data
		buf := &bytes.Buffer{}
		err = resBodyTemplate.Execute(buf, map[string]any{
			"req": request,
			"res": response,
			"err": dataerr,
		})
		if err != nil {
			return util.ErrResponseMsg("Failed to execute response template: %v", err), nil
		} else {
			res.StatusCode = http.StatusOK
			res.Body = io.NopCloser(buf)
			if responseContentType == "" {
				res.Header.Set("Content-Type", constants.MIME_HTML)
				res.Header.Del("Content-Length")
			}
		}
	} else if len(subs) > 0 && res.Body != nil {
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
			res.Body.Close()
			if err != nil {
				return util.ErrResponseMsg("Failed to read body: %v", err), nil
			} else {
				data := string(body) // for now, assume UTF-8
				for sub, replace := range subs {
					data = strings.ReplaceAll(data, sub, replace)
				}
				res.Header.Del("Content-Length")
				res.Body = io.NopCloser(strings.NewReader(data))
			}
		}
	}

	if respass != "" {
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return util.ErrResponseMsg("Failed to read body: %v", err), nil
		}
		cipher, err := util.GetDeterministicCipher(respass)
		if err != nil {
			return util.ErrResponseMsg("Failed to get resbody cipher: %v", err), nil
		}
		res.Header.Set("Content-Type", constants.MIME_TXT)
		res.Header.Del("Content-Length")
		res.Body = io.NopCloser(strings.NewReader(util.EncryptToBase64String(cipher, body)))
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

func Realkey(key, keytype string) string {
	if keytype != "" {
		key += "." + keytype
	}
	return key
}

func Generate(targetUrl, key, publicurl, prefix string,
	cipher cipher.AEAD) (canonicalurl string, sign, encryptedurl, entryurl, encryptedEntryurl string) {
	urlObj, err := url.Parse(targetUrl)
	signstr := ""
	sgpQuery := url.Values{}
	normalQuery := url.Values{}
	normalUrl := ""
	keytype := ""
	// use the full canonical url
	if err == nil {
		if urlObj.Scheme == "" {
			urlObj.Scheme = "https"
		}
		if urlObj.Host != "" && urlObj.Path == "" {
			urlObj.Path = "/"
		} else if (urlObj.Scheme == "http" || urlObj.Scheme == "https") && urlObj.Host == "" &&
			!strings.Contains(urlObj.Path, "/") {
			// "ipinfo.io" => scheme=, host=, path=ipinfo.io . So add a root path.
			urlObj.Path += "/"
		}
		urlQuery := urlObj.Query()
		for key := range urlQuery {
			if strings.HasPrefix(key, prefix) && len(key) > len(prefix) {
				sgpQuery[key] = urlQuery[key]
			} else {
				normalQuery[key] = urlQuery[key]
			}
		}
		keytype = urlQuery.Get(prefix + KEYTYPE_STRING)
		urlQuery.Del(prefix + SIGN_STRING)
		urlQuery.Del(prefix + KEYTYPE_STRING)
		urlObj.RawQuery = urlQuery.Encode() // query key sorted
		canonicalurl = urlObj.String()
		if urlQuery[prefix+SCOPE_STRING] != nil {
			var scopes []string
			for _, scope := range urlQuery[prefix+SCOPE_STRING] {
				if scope != "" {
					scopes = append(scopes, scope)
				}
			}
			if len(scopes) > 0 {
				for key := range urlQuery {
					if !strings.HasPrefix(key, prefix) {
						urlQuery.Del(key)
					}
				}
				signstr = "?" + urlQuery.Encode()
			}
		}
		urlObj.RawQuery = normalQuery.Encode()
		normalUrl = urlObj.String()
	}
	if canonicalurl == "" {
		canonicalurl = targetUrl
	}
	if signstr == "" {
		signstr = canonicalurl
	}
	if key != "" {
		if urlObj.Scheme != "data" {
			mac := hmac.New(sha256.New, []byte(Realkey(key, keytype)))
			mac.Write([]byte(signstr))
			sign = hex.EncodeToString(mac.Sum(nil))
			sgpQuery.Set(prefix+SIGN_STRING, sign)
			if publicurl != "" {
				if normalUrl != "" {
					entryurl = fmt.Sprintf("%s/%s/%s", strings.TrimSuffix(publicurl, "/"), sgpQuery.Encode(), normalUrl)
				} else {
					if keytype != "" {
						entryurl = fmt.Sprintf("%s/%s%s=%s&%s%s=%s/%s", strings.TrimSuffix(publicurl, "/"),
							prefix, KEYTYPE_STRING, url.QueryEscape(keytype), prefix, SIGN_STRING, sign, canonicalurl)
					} else {
						entryurl = fmt.Sprintf("%s/%s%s=%s/%s", strings.TrimSuffix(publicurl, "/"),
							prefix, SIGN_STRING, sign, canonicalurl)
					}
				}
			}
		} else {
			entryurl = fmt.Sprintf("%s/%s", strings.TrimSuffix(publicurl, "/"), canonicalurl)
		}
		if cipher != nil {
			if canonicalurlObj, err := url.Parse(canonicalurl); err == nil {
				query := canonicalurlObj.Query()
				if sign != "" {
					query.Set(prefix+SIGN_STRING, sign)
				}
				canonicalurlObj.RawQuery = query.Encode()
				encryptedurl = util.EncryptToString(cipher, []byte(canonicalurlObj.String()))
				encryptedEntryurl = strings.TrimSuffix(publicurl, "/") + "/" + encryptedurl
			}
		}
	} else if publicurl != "" {
		entryurl = fmt.Sprintf("%s/%s", strings.TrimSuffix(publicurl, "/"), canonicalurl)
	}
	return
}

func Decrypt(encryptedurl, publicurl string) (url, encryptedEntryurl string, err error) {
	i := strings.LastIndex(encryptedurl, "?")
	if i != -1 {
		encryptedurl = encryptedurl[:i]
	}
	i = strings.LastIndex(encryptedurl, "/")
	if i != -1 {
		encryptedurl = encryptedurl[i+1:]
	}
	if !constants.EncryptedUrlRegex.MatchString(encryptedurl) {
		return "", "", fmt.Errorf("invalid parameters")
	}
	if flags.Cipher == nil {
		return "", "", fmt.Errorf("key is empty")
	}
	plaindata, err := util.Decrypt(flags.Cipher, encryptedurl)
	if err != nil {
		return "", "", err
	}
	if publicurl != "" {
		encryptedEntryurl = strings.TrimSuffix(publicurl, "/") + "/" + encryptedurl
	}
	return string(plaindata), encryptedEntryurl, nil
}
