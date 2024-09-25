// http basic / digect authentication to the Simplegoproxy server.
// Largely adopted from https://github.com/abbot/go-http-auth .
// See also: https://en.wikipedia.org/wiki/Digest_access_authentication .
package auth

import (
	"bytes"
	"crypto/md5"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagan/simplegoproxy/util"
)

var errUnauthorized = fmt.Errorf("unauthorized")
var errInvalid = fmt.Errorf("invalid authorization header")
var errInvalidCredentials = fmt.Errorf("invalid credentials")

// Headers contains header and error codes used by authenticator.
type Headers struct {
	Authenticate      string // WWW-Authenticate
	Authorization     string // Authorization
	AuthInfo          string // Authentication-Info
	UnauthCode        int    // 401
	UnauthContentType string // text/plain
	UnauthResponse    string // Unauthorized.
}

// NormalHeaders are the regular Headers used by an HTTP Server for
// request authentication.
var NormalHeaders = &Headers{
	Authenticate:      "WWW-Authenticate",
	Authorization:     "Authorization",
	AuthInfo:          "Authentication-Info",
	UnauthCode:        http.StatusUnauthorized,
	UnauthContentType: "text/plain",
	UnauthResponse:    fmt.Sprintf("%d %s\n", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)),
}

// ProxyHeaders are Headers used by an HTTP Proxy server for proxy
// access authentication.
var ProxyHeaders = &Headers{
	Authenticate:      "Proxy-Authenticate",
	Authorization:     "Proxy-Authorization",
	AuthInfo:          "Proxy-Authentication-Info",
	UnauthCode:        http.StatusProxyAuthRequired,
	UnauthContentType: "text/plain",
	UnauthResponse:    fmt.Sprintf("%d %s\n", http.StatusProxyAuthRequired, http.StatusText(http.StatusProxyAuthRequired)),
}

type digestClient struct {
	nc       uint64
	lastSeen int64
}

// Auth is an authenticator implementation for 'Digest' HTTP Authentication scheme (RFC 7616).
//
// Note: this implementation was written following now deprecated RFC
// 2617, and supports only MD5 algorithm.
//
// TODO: Add support for SHA-256 and SHA-512/256 algorithms.
type Auth struct {
	Realm            string
	Opaque           string
	PlainTextSecrets bool
	IgnoreNonceCount bool
	// Headers used by authenticator. Set to ProxyHeaders to use with
	// proxy server. When nil, NormalHeaders are used.
	Headers *Headers

	/*
	   Approximate size of Client's Cache. When actual number of
	   tracked client nonces exceeds
	   ClientCacheSize+ClientCacheTolerance, ClientCacheTolerance*2
	   older entries are purged.
	*/
	ClientCacheSize      int
	ClientCacheTolerance int

	clients map[string]*digestClient
	mutex   sync.RWMutex
}

type digestCacheEntry struct {
	nonce    string
	lastSeen int64
}

type digestCache []digestCacheEntry

func (c digestCache) Less(i, j int) bool {
	return c[i].lastSeen < c[j].lastSeen
}

func (c digestCache) Len() int {
	return len(c)
}

func (c digestCache) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

func (a *Auth) Wrap(wrapped http.HandlerFunc, user, pass string, basic bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if errres, err := a.CheckAuth(r, user, pass, basic); err != nil {
			for key, values := range errres.Header {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			w.WriteHeader(errres.StatusCode)
			io.Copy(w, errres.Body)
		} else {
			wrapped(w, r)
		}
	}
}

// Purge removes count oldest entries from DigestAuth.clients
func (a *Auth) Purge(count int) {
	a.mutex.Lock()
	a.purgeLocked(count)
	a.mutex.Unlock()
}

func (a *Auth) purgeLocked(count int) {
	entries := make([]digestCacheEntry, 0, len(a.clients))
	for nonce, client := range a.clients {
		entries = append(entries, digestCacheEntry{nonce, client.lastSeen})
	}
	cache := digestCache(entries)
	sort.Sort(cache)
	for _, client := range cache[:count] {
		delete(a.clients, client.nonce)
	}
}

// Return "Require auth" http response.
// It's called by CheckAuth when holding mutex.
func (a *Auth) requireAuth(basic bool) *http.Response {
	if basic {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header: http.Header{
				a.Headers.Authenticate: []string{`Basic realm="` + a.Realm + `"`},
			},
			Body: io.NopCloser(strings.NewReader(a.Headers.UnauthResponse)),
		}
	}

	clientsLen := len(a.clients)
	if clientsLen > a.ClientCacheSize+a.ClientCacheTolerance {
		a.Purge(a.ClientCacheTolerance * 2)
	}
	nonce := util.RandString(32)
	a.clients[nonce] = &digestClient{nc: 0, lastSeen: time.Now().UnixNano()}

	return &http.Response{
		StatusCode: http.StatusUnauthorized,
		Header: http.Header{
			"Content-Type": []string{a.Headers.UnauthContentType},
			a.Headers.Authenticate: []string{fmt.Sprintf(
				`Digest realm="%s", nonce="%s", opaque="%s", algorithm=MD5, qop="auth"`,
				a.Realm, nonce, a.Opaque)},
		},
		Body: io.NopCloser(strings.NewReader(a.Headers.UnauthResponse)),
	}
}

// DigestAuthParams parses Authorization header from the
// http.Request. Returns a map of auth parameters or nil if the header
// is not a valid parsable Digest auth header.
func DigestAuthParams(authorization string) map[string]string {
	s := strings.SplitN(authorization, " ", 2)
	if len(s) != 2 || s[0] != "Digest" {
		return nil
	}

	return ParsePairs(s[1])
}

// CheckAuth checks whether the request contains valid authentication
// data. If not, return a "RequireAuth" http response with an error.
func (a *Auth) CheckAuth(r *http.Request, username, password string, basic bool) (errres *http.Response, err error) {
	if basic {
		user, pass, ok := r.BasicAuth()
		if !ok {
			return a.requireAuth(basic), errUnauthorized
		}
		usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(user))
		passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(pass))
		userAndPassOk := subtle.ConstantTimeSelect(usernameMatch, passwordMatch, 0) == 0
		if userAndPassOk {
			return a.requireAuth(basic), errUnauthorized
		}
		return nil, nil
	}
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	auth := DigestAuthParams(r.Header.Get(a.Headers.Authorization))
	if auth == nil {
		return a.requireAuth(basic), errUnauthorized
	}
	// RFC2617 Section 3.2.1 specifies that unset value of algorithm in
	// WWW-Authenticate Response header should be treated as
	// "MD5". According to section 3.2.2 the "algorithm" value in
	// subsequent Request Authorization header must be set to whatever
	// was supplied in the WWW-Authenticate Response header. This
	// implementation always returns an algorithm in WWW-Authenticate
	// header, however there seems to be broken clients in the wild
	// which do not set the algorithm. Assume the unset algorithm in
	// Authorization header to be equal to MD5.
	if _, ok := auth["algorithm"]; !ok {
		auth["algorithm"] = "MD5"
	}
	if a.Opaque != auth["opaque"] || auth["algorithm"] != "MD5" || auth["qop"] != "auth" {
		return a.requireAuth(basic), errInvalid
	}

	// Check if the requested URI matches auth header
	if r.RequestURI != auth["uri"] {
		// We allow auth["uri"] to be a full path prefix of request-uri
		// for some reason lost in history, which is probably wrong, but
		// used to be like that for quite some time
		// (https://tools.ietf.org/html/rfc2617#section-3.2.2 explicitly
		// says that auth["uri"] is the request-uri).
		//
		// TODO: make an option to allow only strict checking.
		switch u, err := url.Parse(auth["uri"]); {
		case err != nil:
			return a.requireAuth(basic), errInvalid
		case r.URL == nil:
			return a.requireAuth(basic), errInvalid
		case len(u.Path) > len(r.URL.Path):
			return a.requireAuth(basic), errInvalid
		case !strings.HasPrefix(r.URL.Path, u.Path):
			return a.requireAuth(basic), errInvalid
		}
	}

	// HA1 = MD5(username:realm:password)
	HA1 := H(auth["username"] + ":" + a.Realm + ":" + password)
	if a.PlainTextSecrets {
		HA1 = H(auth["username"] + ":" + a.Realm + ":" + HA1)
	}
	HA2 := H(r.Method + ":" + auth["uri"])
	KD := H(strings.Join([]string{HA1, auth["nonce"], auth["nc"], auth["cnonce"], auth["qop"], HA2}, ":"))

	if subtle.ConstantTimeCompare([]byte(KD), []byte(auth["response"])) != 1 {
		return a.requireAuth(basic), errInvalidCredentials
	}

	// At this point crypto checks are completed and validated.
	// Now check if the session is valid.

	nc, err := strconv.ParseUint(auth["nc"], 16, 64)
	if err != nil {
		return a.requireAuth(basic), errInvalidCredentials
	}

	client, ok := a.clients[auth["nonce"]]
	if !ok {
		return a.requireAuth(basic), errInvalidCredentials
	}
	if client.nc != 0 && client.nc >= nc && !a.IgnoreNonceCount {
		return a.requireAuth(basic), errInvalidCredentials
	}
	// client.nc = nc
	// client.lastSeen = time.Now().UnixNano()
	// respHA2 := H(":" + auth["uri"])
	// rspauth := H(strings.Join([]string{HA1, auth["nonce"], auth["nc"], auth["cnonce"], auth["qop"], respHA2}, ":"))
	// info := fmt.Sprintf(`qop="auth", rspauth="%s", cnonce="%s", nc="%s"`, rspauth, auth["cnonce"], auth["nc"])
	return nil, nil
}

// Default values for ClientCacheSize and ClientCacheTolerance for DigestAuth
const (
	DefaultClientCacheSize      = 1000
	DefaultClientCacheTolerance = 100
)

// NewAuthenticator generates a new DigestAuth object
func NewAuthenticator(realm string, proxy bool) *Auth {
	var headers *Headers
	if proxy {
		headers = ProxyHeaders
	} else {
		headers = NormalHeaders
	}
	return &Auth{
		Opaque:               util.RandString(32),
		Realm:                realm,
		PlainTextSecrets:     false,
		ClientCacheSize:      DefaultClientCacheSize,
		ClientCacheTolerance: DefaultClientCacheTolerance,
		clients:              map[string]*digestClient{},
		Headers:              headers,
	}
}

// ParseList parses a comma-separated list of values as described by
// RFC 2068 and returns list elements.
//
// Lifted from https://code.google.com/p/gorilla/source/browse/http/parser/parser.go
// which was ported from urllib2.parse_http_list, from the Python
// standard library.
func ParseList(value string) []string {
	var list []string
	var escape, quote bool
	b := new(bytes.Buffer)
	for _, r := range value {
		switch {
		case escape:
			b.WriteRune(r)
			escape = false
		case quote:
			if r == '\\' {
				escape = true
			} else {
				if r == '"' {
					quote = false
				}
				b.WriteRune(r)
			}
		case r == ',':
			list = append(list, strings.TrimSpace(b.String()))
			b.Reset()
		case r == '"':
			quote = true
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	// Append last part.
	if s := b.String(); s != "" {
		list = append(list, strings.TrimSpace(s))
	}
	return list
}

// ParsePairs extracts key/value pairs from a comma-separated list of
// values as described by RFC 2068 and returns a map[key]value. The
// resulting values are unquoted. If a list element doesn't contain a
// "=", the key is the element itself and the value is an empty
// string.
//
// Lifted from https://code.google.com/p/gorilla/source/browse/http/parser/parser.go
func ParsePairs(value string) map[string]string {
	m := make(map[string]string)
	for _, pair := range ParseList(strings.TrimSpace(value)) {
		switch i := strings.Index(pair, "="); {
		case i < 0:
			// No '=' in pair, treat whole string as a 'key'.
			m[pair] = ""
		case i == len(pair)-1:
			// Malformed pair ('key=' with no value), keep key with empty value.
			m[pair[:i]] = ""
		default:
			v := pair[i+1:]
			if v[0] == '"' && v[len(v)-1] == '"' {
				// Unquote it.
				v = v[1 : len(v)-1]
			}
			m[pair[:i]] = v
		}
	}
	return m
}

// H function for MD5 algorithm (returns a lower-case hex MD5 digest)
func H(data string) string {
	digest := md5.New()
	digest.Write([]byte(data))
	return fmt.Sprintf("%x", digest.Sum(nil))
}
