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
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/dop251/goja"
	"github.com/icholy/replace"
	"github.com/vincent-petithory/dataurl"
	"golang.org/x/text/transform"

	"github.com/sagan/simplegoproxy/auth"
	"github.com/sagan/simplegoproxy/constants"
	"github.com/sagan/simplegoproxy/flags"
	"github.com/sagan/simplegoproxy/tpl"
	"github.com/sagan/simplegoproxy/util"
)

const (
	HEADER_PREFIX          = "header_"
	RESPONSE_HEADER_PREFIX = "resheader_"
	SUB_PREFIX             = "sub_"
	SUBR_PREFIX            = "subr_"
	SUBB_PREFIX            = "subb_"
	SUBTYPE_STRING         = "subtype"
	SUBPATH_STRING         = "subpath"
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
	MUTESTATUS_STRING      = "mutestatus"
	MUTETYPE_STRING        = "mutetype"
	MUTEPATH_STRING        = "mutepath"
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
	TPLMODE_STRING         = "tplmode"
	TPLPATH_STRING         = "tplpath"
	TPLTYPE_STRING         = "tpltype"
	INDEXFILE_STRING       = "indexfile"
	MD2HTML_STRING         = "md2html"
	DEBUG_STRING           = "debug"
	EPATH_STRING           = "epath" // allow subpath in encrypted url
	SALT_STRING            = "salt"
	FLAG_STRING            = "flag"
	ARG_SRING              = "arg"
	ARGS_SRING             = "args"
)

// These params do not participate in url signing: sign, keytype, salt.
var NoSignParameters = []string{SIGN_STRING, KEYTYPE_STRING, SALT_STRING}

// These params are allowed in query string of an alias url: salt.
var AliasUrlAllowedQueryParameters = []string{SALT_STRING}

var errNotFound = fmt.Errorf("404 not found")

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
	// in alias mode, url is treated as if signed, but most mod params can not exists in query variables
	var inalias = false
	if r.URL.Fragment != "" {
		for _, flag := range util.SplitCsv(r.URL.Fragment) {
			switch flag {
			case constants.REQ_INALIAS:
				inalias = true
			}
		}
	}
	srcUrlQuery := r.URL.Query()
	if inalias {
		for key := range srcUrlQuery {
			if strings.HasPrefix(key, prefix) && !slices.Contains(AliasUrlAllowedQueryParameters, key[len(prefix):]) {
				srcUrlQuery.Del(key)
			}
		}
	}
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
	if encryltedUrlPath == "" && !inalias && (queryParams.Has(RESPASS_STRING) || queryParams.Has(AUTH_STRING)) {
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
	response, err := FetchUrl(targetUrlObj, r, queryParams, prefix, key, keytypeBlacklist,
		openScopes, openNormal, rcloneBinary, rcloneConfig, encryltedUrlPath, authenticator, inalias, doLog)
	if err != nil {
		if err == errNotFound {
			sendError(w, r, true, doLog, "backend returns 404 not found")
		} else {
			sendError(w, r, supressError || encryltedUrlPath != "", doLog, "Failed to fetch url: %v", err)
		}
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
	inalias, doLog bool) (*http.Response, error) {
	originalUrlObj := *urlObj
	isSigned := queryParams.Get(SIGN_STRING) != ""
	if !inalias || isSigned {
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
	norf := false    // no redirect following
	md2html := false // render markdown to html
	debug := false
	proxy := ""
	impersonate := ""
	timeout := int64(0)
	// bit 0 (1): text template;
	// bit 1 (2): use response body as template;
	// bit 2 (4): do not read original response body as context var;
	// bit 3 (8): always do response body template no matter of url path of original response body type;
	// bit 4 (16): rendered output keep original response content-type unchanged
	var tplmode = 0
	encmode := 0
	authmode := 0
	cookie := ""
	user := ""
	authuser := ""
	body := ""
	forwardBody := false
	templateContents := ""
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
	indexfile := ""
	// password to encrypt final response body to client
	var respass = ""
	var fdheaders []string
	var scopes []string
	var referers []string
	var origines []string
	var tplpathes []string // suffixes, if url ends with any suffix, do template. e.g. ".sgp.txt"
	var subpathes []string // suffixes, if url ends with any suffix, do substitutions.
	// Mediatypes, if response has any of content type, do template. e.g. "txt" or "text/plain".
	// Could be a ["*"] single element slice to allow all.
	var tpltypes []string
	var mutepathes []string // do not sent request to target url server if url path ends with this.
	var mutestatus []string // mute original http response of these status codes.
	var mutetypes []string  // mute original http response of these content types
	// Do subs for these content-types. could be a ["*"] single element slice to allow all.
	var subtypes []string
	// bitwise flags. bit 0: don't parse each value of array values as csv
	var sgpflag = 0
	if f := queryParams.Get(FLAG_STRING); f != "" {
		if sgpflag, err = strconv.Atoi(f); err != nil || sgpflag < 0 {
			return nil, fmt.Errorf("invalid flag: %v", err)
		}
	}
	now := time.Now().Unix()
	for key := range queryParams {
		var values []string
		values = append(values, queryParams[key]...)
		if (isSigned || inalias) && !slices.Contains(NoSignParameters, key) {
			for i := range values {
				values[i] = applyEnv(values[i])
			}
		}
		value := values[0]
		switch key {
		case FLAG_STRING, EID_STRING, EPATH_STRING, ARG_SRING, ARGS_SRING:
			// do nothing
		case TPLMODE_STRING:
			tplmode, err = strconv.Atoi(value)
			if err != nil || tplmode < 0 {
				return nil, fmt.Errorf("invalid tplmode: %v", err)
			}
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
		case STATUS_STRING:
			status, err = strconv.Atoi(value)
			if err != nil || (status != 0 && status != -1 && (status < 100 || status > 599)) {
				return nil, fmt.Errorf("invalid status %q: %v", value, err)
			}
		case TPLPATH_STRING:
			tplpathes = parseArrayParameters(sgpflag, values, false, nil)
		case SUBPATH_STRING:
			subpathes = parseArrayParameters(sgpflag, values, false, nil)
		case TPLTYPE_STRING:
			tpltypes = parseArrayParameters(sgpflag, values, false, normalizeTypeParameter)
		case MUTESTATUS_STRING:
			mutestatus = parseArrayParameters(sgpflag, values, false, nil)
		case MUTEPATH_STRING:
			mutepathes = parseArrayParameters(sgpflag, values, false, nil)
		case MUTETYPE_STRING:
			mutetypes = parseArrayParameters(sgpflag, values, true, func(typ string) string {
				if strings.HasPrefix(typ, "!") {
					return "!" + normalizeTypeParameter(typ[1:])
				}
				return normalizeTypeParameter(typ)
			})
		case SUBTYPE_STRING:
			subtypes = parseArrayParameters(sgpflag, values, false, normalizeTypeParameter)
		case SALT_STRING:
			salt = value
		case INDEXFILE_STRING:
			indexfile = value
		case MD2HTML_STRING:
			md2html = true
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
			fdheaders = parseArrayParameters(sgpflag, values, false, nil)
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
			if strings.ContainsAny(value, constants.LINE_BREAKS) {
				return nil, fmt.Errorf("keytype can not contain line breaks")
			}
			keytype = value
		case SCOPE_STRING:
			scopes = parseArrayParameters(sgpflag, values, false, nil)
		case REFERER_STRING:
			referers = parseArrayParameters(sgpflag, values, true, nil)
		case ORIGIN_STRING:
			origines = parseArrayParameters(sgpflag, values, true, nil)
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
	effectiveUrlPath := urlObj.Path
	if strings.HasSuffix(effectiveUrlPath, "/") && indexfile != "" {
		effectiveUrlPath += indexfile
	}
	if responseContentType != "" {
		if responseContentType == "*" { // guess from url path
			if strings.HasSuffix(effectiveUrlPath, "/") {
				responseContentType = constants.MIME_HTML
			} else {
				responseContentType = util.FileContentType(effectiveUrlPath)
			}
		} else {
			responseContentType = util.ContentType(responseContentType)
		}
		responseMediaType = util.MediaType(responseContentType)
	}
	if len(referers) > 0 && referers[0] != "*" && !util.MatchUrlPatterns(referers, srcReq.Header.Get("Referer"), true) {
		return nil, fmt.Errorf("invalid referer '%s', allowed referers: %v", srcReq.Header.Get("Referer"), referers)
	}
	if len(origines) > 0 && origines[0] != "*" && !util.MatchUrlPatterns(origines, srcReq.Header.Get("Origin"), true) {
		return nil, fmt.Errorf("invalid origin '%s', allowed origines: %v", srcReq.Header.Get("Origin"), origines)
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
			match := false
			if scopes[0] == "*" {
				match = urlObj.Scheme == "http" || urlObj.Scheme == "https"
			} else {
				match = util.MatchUrlPatterns(scopes, urlObj.String(), false)
			}
			if !match {
				return nil, fmt.Errorf(`invalid url %s for scopes %v`, urlObj, scopes)
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
		for _, fdheader := range fdheaders {
			switch fdheader {
			case "\n":
				forwardHeaders = nil
			case "*":
				for h := range srcReq.Header {
					forwardHeaders = append(forwardHeaders, h)
				}
			default:
				forwardHeaders = append(forwardHeaders, fdheader)
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

	if len(mutepathes) > 0 {
		mute := func() bool {
			for _, mp := range mutepathes {
				switch {
				case mp == "*":
					if strings.HasSuffix(effectiveUrlPath, "/") || path.Ext(effectiveUrlPath) != "" {
						return true
					}
				case strings.HasPrefix(mp, "!"):
					if !strings.HasSuffix(effectiveUrlPath, mp[1:]) {
						return true
					}
				default:
					if strings.HasSuffix(effectiveUrlPath, mp) {
						return true
					}
				}
			}
			return false
		}()
		if mute {
			return nil, errNotFound
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
		if strings.HasSuffix(urlStr, "/") && indexfile != "" {
			urlStr += indexfile
		}
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
	originalResponseMediaType := util.MediaType(res.Header.Get("Content-Type"))

	mute := false
	if !mute && len(mutestatus) > 0 {
		mute = func() bool {
			for _, ms := range mutestatus {
				switch {
				case ms == "*":
					if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusPartialContent {
						return true
					}
				case strings.HasPrefix(ms, "!"):
					if s, err := strconv.Atoi(ms[1:]); err == nil && res.StatusCode != s {
						return true
					}
				default:
					if s, err := strconv.Atoi(ms); err == nil && res.StatusCode == s {
						return true
					}
				}
			}
			return false
		}()
	}
	if !mute && len(mutetypes) > 0 {
		mute = func() bool {
			for _, mt := range mutetypes {
				switch {
				case mt == "*":
					if originalResponseMediaType != constants.MEDIATYPE_TXT &&
						originalResponseMediaType != constants.MEDIATYPE_HTML {
						return true
					}
				case strings.HasPrefix(mt, "!"):
					if originalResponseMediaType != mt[1:] {
						return true
					}
				default:
					if originalResponseMediaType == mt {
						return true
					}
				}
			}
			return false
		}()
	}
	if mute {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, errNotFound
	}

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

	dosub := func() bool {
		if (len(subs) == 0 && len(subrs) == 0 && len(subbs) == 0) || res.Body == nil {
			return false
		}
		if forcesub {
			return true
		}
		if len(subpathes) > 0 && subpathes[0] != "*" && !slices.ContainsFunc(subpathes, func(suffix string) bool {
			return strings.HasSuffix(effectiveUrlPath, suffix)
		}) {
			return false
		}
		if len(subtypes) > 0 {
			if subtypes[0] != "*" && !slices.Contains(subtypes, originalResponseMediaType) {
				return false
			}
		} else if !util.IsTextualMediaType(originalResponseMediaType) {
			return false
		}
		return true
	}()
	if dosub {
		res.Body, err = NewReadCloserReplacer(res.Body, subs, subrs, subbs)
		if err != nil {
			return nil, fmt.Errorf("failed to create body replacer: %v", err)
		}
		deleteContentHeaders(res.Header)
	}

	var tplStatus int
	var tplHeader http.Header
	var jsvm *goja.Runtime
	var tplBody io.ReadCloser
	var resBodyTemplate constants.Template
	if templateContents != "" || tplmode&2 != 0 {
		dotpl := func() bool {
			if tplmode&2 != 0 && res.Body == nil {
				return false
			}
			if tplmode&8 != 0 {
				return true
			}
			if len(tplpathes) > 0 && tplpathes[0] != "*" && !slices.ContainsFunc(tplpathes, func(suffix string) bool {
				return strings.HasSuffix(effectiveUrlPath, suffix)
			}) {
				return false
			}
			if len(tpltypes) > 0 {
				if tpltypes[0] != "*" && !slices.Contains(tpltypes, originalResponseMediaType) {
					return false
				}
			} else if !util.IsTextualMediaType(originalResponseMediaType) {
				return false
			}
			return true
		}()
		if dotpl {
			tplHeader = http.Header{}
			jsvm = goja.New()
			getTemplate := func(contents string, usehtml bool) (tplobj constants.Template, err error) {
				// dummy side effect template funcs to update request-scope state
				funcs := template.FuncMap{
					"eval": func(input any) any {
						return tpl.Eval(jsvm, input)
					},
					"set_status": func(input any) string {
						tplStatus, _ = strconv.Atoi(tpl.Any2string(input))
						return ""
					},
					"set_body": func(body any) string {
						if body == nil {
							tplBody = io.NopCloser(bytes.NewReader(nil))
						} else {
							switch v := body.(type) {
							case io.ReadCloser:
								tplBody = v
							case io.Reader:
								tplBody = io.NopCloser(v)
							case []byte:
								tplBody = io.NopCloser(bytes.NewReader(v))
							case string:
								tplBody = io.NopCloser(strings.NewReader(v))
							default:
								tplBody = io.NopCloser(strings.NewReader(fmt.Sprint(v)))
							}
						}
						return ""
					},
					"set_header": func(key, value any) string {
						keyStr := tpl.Any2string(key)
						valueStr := tpl.Any2string(value)
						if valueStr == "" {
							tplHeader.Del(keyStr)
						} else {
							tplHeader.Set(keyStr, valueStr)
						}
						return ""
					},
				}
				if usehtml {
					if isSigned || inalias {
						tplobj, err = htmlTemplate.New("template").Funcs(sprig.FuncMap()).Funcs(tpl.TemplateFuncMap).Funcs(funcs).
							Parse(contents)
					} else {
						tplobj, err = htmlTemplate.New("template").Funcs(funcs).Parse(contents)
					}
				} else {
					if isSigned || inalias {
						tplobj, err = template.New("template").Funcs(sprig.FuncMap()).Funcs(tpl.TemplateFuncMap).Funcs(funcs).
							Parse(contents)
					} else {
						tplobj, err = template.New("template").Funcs(funcs).Parse(contents)
					}
				}
				return tplobj, err
			}
			usehtml := responseMediaType == constants.MEDIATYPE_HTML && tplmode&1 == 0
			if tplmode&2 == 0 {
				if resBodyTemplate, err = getTemplate(templateContents, usehtml); err != nil {
					return nil, fmt.Errorf("invalid template: %v", err)
				}
			} else {
				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				res.Body = nil
				if err != nil {
					return util.ErrResponseMsg("Failed to read body: %v", err), nil
				}
				if resBodyTemplate, err = getTemplate(string(body), usehtml); err != nil {
					return nil, fmt.Errorf("invalid bodytpl template: %v", err)
				}
			}
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
		if responseBodyType == "" && originalResponseMediaType != "" {
			responseBodyType = originalResponseMediaType
		}
		var data any
		if tplmode&2 == 0 {
			if tplmode&4 == 0 {
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
				response["RawBody"] = res.Body
			}
		} else {
			response["Body"] = templateContents
			data, tplerr = util.Unmarshal(responseBodyType, strings.NewReader(templateContents))
		}
		response["Data"] = data

		buf := &bytes.Buffer{}
		now := time.Now().UTC()
		contextVariables := map[string]any{
			"Params": queryParams,
			"SrcReq": srcRequest,
			"Req":    request,
			"Res":    response,
			"Err":    tplerr,
			"Now":    now,
		}
		if jsvm != nil {
			for key, value := range contextVariables {
				jsvm.Set(key, value)
			}
		}
		err = resBodyTemplate.Execute(buf, contextVariables)
		if err != nil {
			return util.ErrResponseMsg("Failed to execute response template: %v", err), nil
		} else {
			if status != -1 {
				res.StatusCode = http.StatusOK
			}
			deleteContentHeaders(res.Header)
			if responseContentType == "" && tplmode&16 == 0 {
				res.Header.Set("Content-Type", constants.MIME_TXT)
			}
			if tplStatus > 0 {
				res.StatusCode = tplStatus
			}
			for key := range tplHeader {
				res.Header.Set(key, tplHeader.Get(key))
			}
			if tplBody != nil {
				res.Body = tplBody
			} else {
				res.Body = io.NopCloser(buf)
			}
		}
	}

	if md2html && res.Body != nil &&
		util.MediaType(util.ContentType(res.Header.Get("Content-Type"))) == constants.MEDIATYPE_MD {
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read body: %v", err)
		}
		html := util.MdToHTML(body)
		res.Body = io.NopCloser(bytes.NewReader(html))
		deleteContentHeaders(res.Header)
		res.Header.Set("Content-Type", constants.MIME_HTML)
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
			if encmode&8 != 0 { // bit 3:  Force treat original body as string
				bodyIsString = true
			} else if encmode&16 != 0 { // bit 4:  Force treat original body as binary
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
				data["body_length"] = len(body)
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

// Delete Content-Length/Encoding/Range headers from header
func deleteContentHeaders(header http.Header) {
	header.Del("Content-Length")
	header.Del("Content-Range")
	header.Del("Content-Encoding")
}

func parseArrayParameters(sgpflag int, values []string, allowEmpty bool, mapper func(string) string) (output []string) {
	for _, value := range values {
		if value == "" {
			if allowEmpty {
				output = append(output, value)
			}
		} else if value == "*" {
			return []string{value}
		} else if sgpflag&1 != 0 {
			output = append(output, value)
		} else {
			for _, v := range util.SplitCsv(value) {
				if v != "" && mapper != nil {
					v = mapper(v)
				}
				if allowEmpty || v != "" {
					output = append(output, v)
				}
			}
		}
	}
	return output
}

// Parse type and return mediatype.
func normalizeTypeParameter(typ string) string {
	if typ == "" {
		return ""
	}
	return util.MediaType(util.ContentType(typ))
}
