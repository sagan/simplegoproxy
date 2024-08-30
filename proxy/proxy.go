package proxy

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	htmlTemplate "html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/icholy/replace"
	"github.com/vincent-petithory/dataurl"
	"golang.org/x/text/transform"

	"github.com/sagan/simplegoproxy/auth"
	"github.com/sagan/simplegoproxy/constants"
	"github.com/sagan/simplegoproxy/flags"
	"github.com/sagan/simplegoproxy/util"
)

const (
	HEADER_PREFIX          = "header_"
	RESPONSE_HEADER_PREFIX = "resheader_"
	SUB_PREFIX             = "sub_"
	SUBR_PREFIX            = "subr_"
	SUBB_PREFIX            = "subb_"
	CORS_STRING            = "cors"
	NOCACHE_STRING         = "nocache"
	NORF_STRING            = "norf"
	PROXY_STRING           = "proxy"
	IMPERSONATE_STRING     = "impersonate"
	TRIMRESHEADER_STRING   = "trimresheader"
	FORCESUB_STRING        = "forcesub"
	NOCSP_STRING           = "nocsp"
	TIMEOUT_STRING         = "timeout"
	INSECURE_STRING        = "insecure"
	COOKIE_STRING          = "cookie"
	USER_STRING            = "user"
	AUTH_STRING            = "auth" // entrypoint url http authorization, username:password
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
	RESPASS_STRING         = "respass" // response body encryption password
	EID_STRING             = "eid"     // encrypt url id
	STATUS_STRING          = "status"
	ENCMODE_STRING         = "encmode"
	AUTHMODE_STRING        = "authmode"
	RESBODYTPL_STRING      = "resbodytpl" // use response body as template. path suffix, e.g. ".sgp.txt"
	DEBUG_STRING           = "debug"
	EPATH_STRING           = "epath" // allow subpath in encrypted url
	SALT_STRING            = "salt"
	ARG_SRING              = "arg"
	ARGS_SRING             = "args"
)

// These params do not participate in url signing, sign, keytype, salt.
var NoSignParameters = []string{SIGN_STRING, KEYTYPE_STRING, SALT_STRING}

type Template interface {
	Execute(wr io.Writer, data any) error
}

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
	openNormal, supressError, doLog bool, enableUnix, enableFile, enableRclone, enableCurl, enableExec bool,
	rcloneBinary, rcloneConfig, curlBinary string, cipher cipher.AEAD, authenticator *auth.Auth) {
	defer r.Body.Close()
	srcUrlQuery := r.URL.Query()
	reqUrlQuery := srcUrlQuery
	targetUrl := r.URL.EscapedPath()
	// If in encrypted url mode, the original encrypted url
	var encryltedUrlPath = ""
	if submatch := constants.EncryptedUrlRegex.FindStringSubmatch(targetUrl); submatch != nil {
		eid := submatch[constants.EncryptedUrlRegex.SubexpIndex("eid")]
		targetUrl = submatch[constants.EncryptedUrlRegex.SubexpIndex("eurl")]
		epath := submatch[constants.EncryptedUrlRegex.SubexpIndex("epath")]
		encryltedUrlPath = targetUrl + epath
		decrypted, err := util.DecryptString(cipher, targetUrl)
		if err != nil {
			sendError(w, r, true, doLog, "Invalid encrypted url: %v", err)
			return
		}
		targetUrl = string(decrypted)
		targetUrlObj, err := url.Parse(targetUrl)
		if err != nil {
			sendError(w, r, true, doLog, "Invalid decrypted target url: %v", err)
			return
		}
		reqUrlQuery = targetUrlObj.Query()
		if qeid := reqUrlQuery.Get(prefix + EID_STRING); qeid != "" && qeid != eid {
			sendError(w, r, true, doLog, fmt.Sprintf("Invalid eid: qeid=%s, eid=%s", qeid, eid))
			return
		}
		if reqUrlQuery.Has(prefix + EPATH_STRING) {
			if epath != "" {
				if escapedEpath, err := url.PathUnescape(epath); err == nil {
					targetUrlObj.Path = strings.TrimSuffix(targetUrlObj.Path, "/") + escapedEpath
				} else {
					targetUrlObj.Path = strings.TrimSuffix(targetUrlObj.Path, "/") + epath
				}
			}
			for key, values := range srcUrlQuery {
				if !strings.HasPrefix(key, prefix) {
					for _, value := range values {
						reqUrlQuery.Add(key, value)
					}
				} else if key == prefix+SALT_STRING {
					reqUrlQuery.Set(key, srcUrlQuery.Get(key))
				}
			}
		} else if epath != "" {
			sendError(w, r, true, doLog, "epath parameter not set, subpath for encrypted url is not supported")
			return
		} else if salt := srcUrlQuery.Get(prefix + SALT_STRING); salt != "" {
			reqUrlQuery.Set(prefix+SALT_STRING, salt)
		}
		targetUrlObj.RawQuery = ""
		targetUrl = targetUrlObj.String()
	}

	var modparams url.Values
	// accept "_sgp_a=1/https://ipcfg.io/json" style request url
	if encryltedUrlPath == "" && strings.HasPrefix(targetUrl, prefix) {
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
		} else {
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
	if encryltedUrlPath == "" && (queryParams.Has(RESPASS_STRING) || queryParams.Has(AUTH_STRING)) {
		sendError(w, r, supressError, doLog, "url with auth or respass must be accessed via encrypted url")
		return
	}
	if strings.HasPrefix(targetUrlObj.Scheme, "curl+") && len(targetUrlObj.Scheme) > 5 {
		if !enableCurl {
			sendError(w, r, supressError || encryltedUrlPath != "", doLog, "curl url is not enabled")
			return
		}
	} else {
		switch targetUrlObj.Scheme {
		case "unix":
			if !enableUnix {
				sendError(w, r, supressError || encryltedUrlPath != "", doLog, "unix domain socket is not enabled")
				return
			}
		case "file":
			if !enableFile {
				sendError(w, r, supressError || encryltedUrlPath != "", doLog, "file url is not enabled")
				return
			}
		case "rclone":
			if !enableRclone {
				sendError(w, r, supressError || encryltedUrlPath != "", doLog, "rclone url is not enabled")
				return
			}
		case "exec":
			if !enableExec {
				sendError(w, r, supressError || encryltedUrlPath != "", doLog, "exec url is not enabled")
				return
			}
		case "http", "https", "data": // do nothing
		default:
			sendError(w, r, supressError || encryltedUrlPath != "", doLog, "unsupported url scheme %q", targetUrlObj.Scheme)
			return
		}
	}
	response, err := FetchUrl(targetUrlObj, r, queryParams, prefix, key,
		keytypeBlacklist, openScopes, openNormal, rcloneBinary, rcloneConfig, encryltedUrlPath, authenticator, doLog)
	if err != nil {
		sendError(w, r, supressError || encryltedUrlPath != "", doLog, "Failed to fetch url: %v", err)
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

func FetchUrl(urlObj *url.URL, srcReq *http.Request, queryParams url.Values, prefix, signkey string, keytypeBlacklist,
	openScopes []string, openNormal bool, rcloneBinary, rcloneConfig, encryltedUrlPath string, authenticator *auth.Auth,
	doLog bool) (*http.Response, error) {
	originalUrlObj := *urlObj
	isSigned := queryParams.Get(SIGN_STRING) != ""
	if isSigned && signkey == "" {
		return nil, fmt.Errorf("url is signed but signkey is not set")
	}
	if !isSigned && signkey != "" {
		open := false
		if openNormal && (urlObj.Scheme == "data" || urlObj.Scheme == "http" || urlObj.Scheme == "https") {
			open = true
		} else if urlObj.Scheme != "data" && util.MatchUrlPatterns(openScopes, urlObj.String(), false) {
			open = true
		}
		if !open {
			return nil, fmt.Errorf(`sign is required but not found`)
		}
	}

	var err error
	header := http.Header{}
	responseHeaders := map[string]string{}
	subs := [][2]string{}
	subrs := [][2]string{}
	subbs := [][2][]byte{}
	cors := false
	insecure := false
	forcesub := false
	trimresheader := false
	nocsp := false
	nocache := false
	norf := false // no redirect following
	debug := false
	useresbodytpl := false
	proxy := ""
	impersonate := ""
	timeout := int64(0)
	encmode := 0
	authmode := 0
	cookie := ""
	user := ""
	authuser := ""
	fdheaders := ""
	body := ""
	forwardBody := false
	templateContents := ""
	var resBodyTemplate Template
	contentType := ""
	responseContentType := ""
	responseMediaType := ""
	responseBodyType := ""
	method := http.MethodGet
	// -1 : force use original http response status
	var status = 0
	keytype := ""
	sign := ""
	salt := ""
	// password to encrypt final response body to client
	var respass = ""
	var scopes []string
	var referers []string
	var origines []string
	now := time.Now().Unix()
	for key := range queryParams {
		var values []string
		values = append(values, queryParams[key]...)
		if isSigned && !slices.Contains(NoSignParameters, key) {
			for i := range values {
				values[i] = applyEnv(values[i])
			}
		}
		value := values[0]
		switch key {
		case ENCMODE_STRING:
			encmode, err = strconv.Atoi(value)
			if err != nil || encmode < 0 {
				return nil, fmt.Errorf("invalid encmode: %v", err)
			}
		case AUTHMODE_STRING:
			authmode, err = strconv.Atoi(value)
			if err != nil || authmode < 0 {
				return nil, fmt.Errorf("invalid authmode: %v", err)
			}
		case EID_STRING, EPATH_STRING, ARG_SRING, ARGS_SRING:
			// do nothing
		case STATUS_STRING:
			status, err = strconv.Atoi(value)
			if err != nil || (status != 0 && status != -1 && (status < 100 || status > 599)) {
				return nil, fmt.Errorf("invalid status %q: %v", value, err)
			}
		case RESBODYTPL_STRING:
			if value == "*" {
				useresbodytpl = true
			} else {
				for _, value := range values {
					if value != "" && strings.HasSuffix(urlObj.Path, value) {
						useresbodytpl = true
						break
					}
				}
			}
		case SALT_STRING:
			salt = value
		case DEBUG_STRING:
			debug = true
		case CORS_STRING:
			cors = true
		case INSECURE_STRING:
			insecure = true
		case FORCESUB_STRING:
			forcesub = true
		case TRIMRESHEADER_STRING:
			trimresheader = true
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
		case AUTH_STRING:
			authuser = value
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
			if value != "" {
				if value == "*" { // guess from url path
					responseContentType = util.FileContentType(urlObj.Path)
				} else {
					responseContentType = util.ContentType(value)
				}
				responseMediaType = util.MediaType(responseContentType)
			}
		case RESBODYTYPE_STRING:
			responseBodyType = value
		case KEYTYPE_STRING:
			if strings.ContainsAny(value, constants.LINE_BREAKS) {
				return nil, fmt.Errorf("keytype can not contain line breaks")
			}
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
						subs = append(subs, [2]string{h, value})
					}
				} else if strings.HasPrefix(key, SUBR_PREFIX) {
					h := key[len(SUBR_PREFIX):]
					if h != "" {
						subrs = append(subrs, [2]string{h, value})
					}
				} else if strings.HasPrefix(key, SUBB_PREFIX) {
					h := key[len(SUBB_PREFIX):]
					spaceCleaner := strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "")
					h = spaceCleaner.Replace(h)
					value = spaceCleaner.Replace(value)
					needle, err := hex.DecodeString(h)
					if err != nil {
						return nil, fmt.Errorf("invalid hexb needle: %v", h)
					}
					replace, err := hex.DecodeString(value)
					if err != nil {
						return nil, fmt.Errorf("invalid hexb replace: %v", h)
					}
					if h != "" {
						subbs = append(subbs, [2][]byte{needle, replace})
					}
				} else {
					return nil, fmt.Errorf("invalid (non-existent) modification parameter '%s'", key)
				}
			}
		}
	}
	if len(referers) > 0 && !util.MatchUrlPatterns(referers, srcReq.Header.Get("Referer"), true) {
		return nil, fmt.Errorf("invalid referer '%s', allowed referers: %v", srcReq.Header.Get("Referer"), referers)
	}
	if len(origines) > 0 && !util.MatchUrlPatterns(origines, srcReq.Header.Get("Origin"), true) {
		return nil, fmt.Errorf("invalid origin '%s', allowed origines: %v", srcReq.Header.Get("Origin"), origines)
	}

	var getTemplate func(contents string) (tpl Template, err error)
	var tplStatus int
	var tplHeader http.Header
	if templateContents != "" || useresbodytpl {
		tplStatus = 0
		tplHeader = http.Header{}
		getTemplate = func(contents string) (tpl Template, err error) {
			// dummy side effect template funcs to update request-scope state
			funcs := template.FuncMap{
				"set_status": func(input any) string {
					tplStatus, _ = strconv.Atoi(any2string(input))
					return ""
				},
				"set_header": func(key, value any) string {
					keyStr := any2string(key)
					valueStr := any2string(value)
					if valueStr == "" {
						tplHeader.Del(keyStr)
					} else {
						tplHeader.Set(keyStr, valueStr)
					}
					return ""
				},
			}
			if responseMediaType == constants.MEDIATYPE_HTML {
				if isSigned {
					tpl, err = htmlTemplate.New("template").Funcs(sprig.FuncMap()).Funcs(templateFuncMap).Funcs(funcs).
						Parse(contents)
				} else {
					tpl, err = htmlTemplate.New("template").Funcs(funcs).Parse(contents)
				}
			} else {
				if isSigned {
					tpl, err = template.New("template").Funcs(sprig.FuncMap()).Funcs(templateFuncMap).Funcs(funcs).
						Parse(contents)
				} else {
					tpl, err = template.New("template").Funcs(funcs).Parse(contents)
				}
			}
			return tpl, err
		}
	}

	if templateContents != "" && !useresbodytpl {
		if resBodyTemplate, err = getTemplate(templateContents); err != nil {
			return nil, fmt.Errorf("invalid template: %v", err)
		}
	}

	// In the beginning of this func, it already checks if sign is required but not signed.
	// So here it only checks if signed, whether the sign is valid.
	if isSigned {
		signUrlQuery := urlObj.Query()
		for key, values := range queryParams {
			signUrlQuery[prefix+key] = values
		}
		for _, key := range NoSignParameters {
			signUrlQuery.Del(prefix + key)
		}
		urlObj.RawQuery = signUrlQuery.Encode()
		signUrl := urlObj.String()
		if urlObj.Scheme != "data" && len(scopes) > 0 {
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
		isSigned = true
	}

	if urlObj.Scheme != "data" {
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
			header.Set("Content-Type", util.ContentType(contentType))
		}
		forwardHeaders := []string{"If-Match", "If-Modified-Since", "If-None-Match", "If-Range",
			"If-Unmodified-Since", "Range"}
		if fdheaders != "" {
			if fdheaders == "*" {
				for h := range srcReq.Header {
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
					method = srcReq.Method
				case ":body":
					forwardBody = true
				default:
					return nil, fmt.Errorf("invalid fdheader %q", h)
				}
			} else {
				if len(header.Values(h)) > 0 || len(srcReq.Header.Values(h)) == 0 {
					continue
				}
				header[h] = srcReq.Header[h]
			}
		}
		if header.Get("Content-Type") == "" && method == http.MethodPost && body != "" {
			header.Set("Content-Type", "application/x-www-form-urlencoded")
		}

		if isSigned && len(scopes) == 0 {
			// Do secret substitution for normal query params if request signing is enabled and is NOT scope signing.
			// Because scope signing do not protect normal query params.
			urlQuery := urlObj.Query()
			for key, values := range urlQuery {
				for i := range values {
					values[i] = applyEnv(values[i])
				}
				urlQuery[key] = values
			}
			urlObj.RawQuery = urlQuery.Encode()
		}
	}

	if authuser != "" {
		username, password, _ := strings.Cut(authuser, ":")
		if username == "" {
			return nil, fmt.Errorf("invalid auth, username must not be empty")
		}
		basic := authmode&1 == 0
		if errres, err := authenticator.CheckAuth(srcReq, username, password, basic); err != nil {
			if doLog {
				log.Printf("Auth failed: %v", err)
			}
			return errres, nil
		}
	}

	var req *http.Request
	var res *http.Response
	if urlObj.Scheme == "data" {
		originalUrlObj.RawQuery = ""
		urlStr := originalUrlObj.String()
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
		urlStr := originalUrlObj.String()
		var reqBody io.Reader
		if forwardBody && srcReq.Body != nil {
			reqBody = srcReq.Body
		} else if body != "" {
			reqBody = strings.NewReader(body)
		}
		req, err = http.NewRequestWithContext(srcReq.Context(), method, urlStr, reqBody)
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
	if trimresheader {
		whitelist := []string{"Content-Type", "Content-Length", "Content-Encoding", "Content-Range"}
		for key := range res.Header {
			if !slices.Contains(whitelist, key) {
				res.Header.Del(key)
			}
		}
	}
	res.Header.Set("Referrer-Policy", "no-referrer")
	if cors {
		res.Header.Set("Access-Control-Allow-Origin", "*")
		res.Header.Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		// res.Header.Set("Access-Control-Allow-Credentials", "true") // it's security vulerable as sgp has admin API now.
		if h := srcReq.Header.Get("Access-Control-Request-Headers"); h != "" {
			res.Header.Set("Access-Control-Allow-Headers", h)
		}
		res.Header.Set("Vary", "Access-Control-Request-Headers")
	}
	if nocsp {
		res.Header.Del("Content-Security-Policy")
		res.Header.Del("Content-Security-Policy-Report-Only")
		res.Header.Del("Cross-Origin-Opener-Policy")
		res.Header.Del("Cross-Origin-Resource-Policy")
		res.Header.Del("Cross-Origin-Embedder-Policy")
		res.Header.Del("X-Content-Security-Policy")
		res.Header.Del("X-WebKit-CSP")
		res.Header.Del("X-XSS-Protection")
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
		res.Header.Set("Content-Type", responseContentType)
	}

	if (len(subs) > 0 || len(subrs) > 0 || len(subbs) > 0) && res.Body != nil &&
		(forcesub || util.IsTextualMediaType(util.MediaType(res.Header.Get("Content-Type")))) {
		res.Body, err = NewReadCloserReplacer(res.Body, subs, subrs, subbs)
		if err != nil {
			return nil, fmt.Errorf("failed to create body replacer: %v", err)
		}
		res.Header.Del("Content-Length")
		res.Header.Del("Content-Encoding")
	}

	if useresbodytpl && res.Body != nil {
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		res.Body = nil
		if err != nil {
			return util.ErrResponseMsg("Failed to read body: %v", err), nil
		}
		if resBodyTemplate, err = getTemplate(string(body)); err != nil {
			return nil, fmt.Errorf("invalid bodytpl template: %v", err)
		}
	}

	if resBodyTemplate != nil {
		var tplerr error
		var srcRequest = map[string]any{
			"RemoteAddr": srcReq.RemoteAddr,
			"Header":     srcReq.Header,
			"URL":        srcReq.URL,
		}
		var request = map[string]any{}
		if req != nil {
			request["Method"] = req.Method
			request["Header"] = req.Header
			request["URL"] = req.URL
		} else {
			request["Method"] = http.MethodGet
			request["Header"] = http.Header{}
		}
		var response = map[string]any{
			"Status": res.StatusCode,
			"Header": res.Header,
		}
		if responseBodyType == "" && originalResponseContentType != "" {
			responseBodyType = util.MediaType(originalResponseContentType)
		}
		var data any
		if !useresbodytpl {
			var body []byte
			if res.Body != nil {
				body, err = io.ReadAll(res.Body)
				res.Body.Close()
				if err != nil {
					return util.ErrResponseMsg("Failed to read body: %v", err), nil
				}
				data, tplerr = util.Unmarshal(responseBodyType, bytes.NewReader(body))
			}
			response["Body"] = string(body)
		} else {
			response["Body"] = templateContents
			data, tplerr = util.Unmarshal(responseBodyType, strings.NewReader(templateContents))
		}
		response["Data"] = data

		buf := &bytes.Buffer{}
		now := time.Now().UTC()
		err = resBodyTemplate.Execute(buf, map[string]any{
			"Params": queryParams,
			"SrcReq": srcRequest,
			"Req":    request,
			"Res":    response,
			"Err":    tplerr,
			"Now":    now,
		})
		if err != nil {
			return util.ErrResponseMsg("Failed to execute response template: %v", err), nil
		} else {
			if status != -1 {
				res.StatusCode = http.StatusOK
			}
			res.Body = io.NopCloser(buf)
			res.Header.Del("Content-Length")
			res.Header.Del("Content-Encoding")
			if responseContentType == "" {
				res.Header.Set("Content-Type", constants.MIME_TXT)
			}
			if tplStatus > 0 {
				res.StatusCode = tplStatus
			}
			for key := range tplHeader {
				res.Header.Set(key, tplHeader.Get(key))
			}
		}
	}

	if respass != "" && res.Body != nil {
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read body: %v", err)
		}
		cipher, err := util.GetCipher(respass, salt)
		if err != nil {
			return nil, fmt.Errorf("failed to get resbody cipher: %v", err)
		}
		mediaType := util.MediaType(res.Header.Get("Content-Type"))
		var data map[string]any
		protectHeaders := encmode&4 != 0 || encmode&2 == 0
		if protectHeaders {
			data = map[string]any{
				"status":        res.StatusCode,
				"header":        res.Header,
				"encrypted_url": encryltedUrlPath,
				"request_query": srcReq.URL.RawQuery,
				"date":          time.Now().UTC().Format("2006-01-02T15:04:05Z"),
				"source_addr":   srcReq.RemoteAddr,
			}
			res.StatusCode = http.StatusOK
			res.Header = http.Header{}
		}
		if encmode&4 != 0 { // bit 2: whole meta + body in encrypted body
			bodyIsString := false
			if encmode&8 == 1 { // bit 3:  Force treat original body as string
				bodyIsString = true
			} else if encmode&16 == 1 { // bit 4:  Force treat original body as binary
				bodyIsString = false
			} else if util.IsTextualMediaType(mediaType) {
				bodyIsString = true
			}
			if bodyIsString {
				data["body"] = string(body)
				data["body_encoding"] = ""
			} else {
				data["body"] = base64.StdEncoding.EncodeToString(body)
				data["body_encoding"] = "base64"
			}
			dataJson, err := json.Marshal(data)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal data json")
			}
			body = util.Encrypt(cipher, []byte(dataJson))
		} else {
			body = util.Encrypt(cipher, body)
			if encmode&2 == 0 { // bit 1 : encrypt body only
				hash := sha256.New()
				hash.Write(body)
				sha256hash := hash.Sum(nil)
				data["body_sha256"] = hex.EncodeToString(sha256hash)
				metaJson, err := json.Marshal(data)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal meta json")
				}
				res.Header.Set("X-Encryption-Meta", util.EncryptToBase64String(cipher, metaJson))
			}
		}
		if encmode&1 != 0 { // bit 0 : sent cipertext as binary (instead of base64)
			res.Header.Set("Content-Type", constants.DEFAULT_MIME)
			res.Body = io.NopCloser(bytes.NewReader(body))
		} else {
			res.Header.Set("Content-Type", constants.MIME_TXT)
			res.Body = io.NopCloser(strings.NewReader(base64.StdEncoding.EncodeToString(body)))
		}
	}

	if status > 0 {
		res.StatusCode = status
	}
	return res, nil
}

var envRegexp = regexp.MustCompile("__SGPENV_[_a-zA-Z][_a-zA-Z0-9]*?__")

// replace all  __SGPENV_ABC__ style substrings with ABC env value.
func applyEnv(str string) string {
	return envRegexp.ReplaceAllStringFunc(str, func(s string) string {
		env := s[9 : len(s)-2]
		if strings.HasPrefix(env, constants.SGP_ENV_PREFIX) {
			return s
		}
		if variable, ok := os.LookupEnv(env); ok {
			return variable
		}
		return s
	})
}

// key and keytype are guaranteed to do not contain \n.
// Put keytype (plaintext) first, to increase security against length extension attack.
// See https://en.wikipedia.org/wiki/Length_extension_attack .
// We use HMAC to derive signing key from Realkey() output, so it's only a double security.
func Realkey(key, keytype string) string {
	if keytype != "" {
		key = keytype + "\n" + key
	}
	return key
}

func Generate(targetUrl, eid, key, publicurl, prefix string,
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
		for _, key := range NoSignParameters {
			urlQuery.Del(prefix + key)
		}
		urlObj.RawQuery = urlQuery.Encode() // query key sorted
		canonicalurl = urlObj.String()
		if urlObj.Scheme != "data" && urlQuery[prefix+SCOPE_STRING] != nil {
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
		if cipher != nil {
			if canonicalurlObj, err := url.Parse(canonicalurl); err == nil {
				query := canonicalurlObj.Query()
				if sign != "" {
					query.Set(prefix+SIGN_STRING, sign)
				}
				if keytype != "" {
					query.Set(prefix+KEYTYPE_STRING, keytype)
				}
				canonicalurlObj.RawQuery = query.Encode()
				encryptedurl = util.EncryptToString(cipher, []byte(canonicalurlObj.String()))
				if eid != "" {
					encryptedurl = eid + "_" + encryptedurl
				}
				if query.Has(prefix + EPATH_STRING) {
					encryptedurl += "/"
				}
				encryptedEntryurl = strings.TrimSuffix(publicurl, "/") + "/" + encryptedurl
			}
		}
	} else if publicurl != "" {
		entryurl = fmt.Sprintf("%s/%s", strings.TrimSuffix(publicurl, "/"), canonicalurl)
	}
	return
}

func Parse(prefix, fromurl, publicurl string) (plainurl, encryptedEntryurl, entryurl, eid string, err error) {
	fromurl = strings.TrimPrefix(fromurl, publicurl)
	if submatch := constants.EncryptedUrlRegex.FindStringSubmatch(fromurl); submatch != nil {
		if flags.Cipher == nil {
			return "", "", "", "", fmt.Errorf("key is empty")
		}
		eid := submatch[constants.EncryptedUrlRegex.SubexpIndex("eid")]
		ciphertext := submatch[constants.EncryptedUrlRegex.SubexpIndex("eurl")]
		plaindata, err := util.DecryptString(flags.Cipher, ciphertext)
		if err != nil {
			return "", "", "", "", err
		}
		plainurl = string(plaindata)
		if eid != "" {
			if urlObj, err := url.Parse(plainurl); err != nil || urlObj.Query().Get(prefix+EID_STRING) != eid {
				return "", "", "", "", fmt.Errorf("invalid eid")
			}
		}
		if publicurl != "" {
			encryptedEntryurl = strings.TrimSuffix(publicurl, "/") + "/" + fromurl
		}
	} else {
		targetUrl := fromurl
		var modparams url.Values
		// accept "_sgp_a=1/https://ipcfg.io/json" style url
		if strings.HasPrefix(fromurl, prefix) {
			index := strings.Index(fromurl, "/")
			if index == -1 {
				return "", "", "", "", fmt.Errorf("invalid url")
			}
			modparamsStr := targetUrl[:index]
			targetUrl = targetUrl[index+1:]
			modparams, err = url.ParseQuery(modparamsStr)
			if err != nil {
				return "", "", "", "", fmt.Errorf("invalid url")
			}
		}
		targetUrlObj, err := url.Parse(targetUrl)
		if err != nil {
			return "", "", "", "", fmt.Errorf("invalid url")
		}
		if targetUrlObj.Scheme == "" {
			targetUrlObj.Scheme = "https"
		}
		targetUrlQuery := targetUrlObj.Query()
		for key, values := range modparams {
			if !strings.HasPrefix(key, prefix) {
				return "", "", "", "", fmt.Errorf("invalid url")
			}
			for _, value := range values {
				targetUrlQuery.Add(key, value)
			}
		}
		for _, key := range NoSignParameters {
			targetUrlQuery.Del(key)
		}
		targetUrlObj.RawQuery = targetUrlQuery.Encode()
		plainurl = targetUrlObj.String()
		if publicurl != "" {
			entryurl = strings.TrimSuffix(publicurl, "/") + "/" + fromurl
		}
	}

	return plainurl, encryptedEntryurl, entryurl, eid, nil
}

type ReadCloserReplacer struct {
	io.Reader
	src io.Reader
}

func (r *ReadCloserReplacer) Close() error {
	if c := r.src.(io.Closer); c != nil {
		return c.Close()
	}
	return nil
}

// Return a ReadCloser stream that do find-and-replacements to src on the fly.
// The Close func of returned value is no-op if src ifself is not a Closer.
func NewReadCloserReplacer(src io.Reader, subs [][2]string, subrs [][2]string,
	subbs [][2][]byte) (io.ReadCloser, error) {
	var tt []transform.Transformer
	for _, sub := range subs {
		tt = append(tt, replace.String(sub[0], sub[1]))
	}
	for _, subr := range subrs {
		regex, err := regexp.Compile(subr[0])
		if err != nil {
			return nil, fmt.Errorf("failed to compile subr rule %v: %v", subr, err)
		}
		tt = append(tt, replace.RegexpString(regex, subr[1]))
	}
	for _, subb := range subbs {
		tt = append(tt, replace.Bytes(subb[0], subb[1]))
	}
	dst := replace.Chain(src, tt...)
	return &ReadCloserReplacer{dst, src}, nil
}
