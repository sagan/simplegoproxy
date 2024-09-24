package main

import (
	"flag"
	"fmt"
	"log"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/google/btree"

	"github.com/sagan/simplegoproxy/admin"
	"github.com/sagan/simplegoproxy/auth"
	"github.com/sagan/simplegoproxy/constants"
	"github.com/sagan/simplegoproxy/flags"
	"github.com/sagan/simplegoproxy/proxy"
	"github.com/sagan/simplegoproxy/util"
	"github.com/sagan/simplegoproxy/version"
)

func init() {
	mime.AddExtensionType(".toml", "application/toml")
	mime.AddExtensionType(".yaml", "application/yaml")
	mime.AddExtensionType(".gotmpl", "text/plain")
	mime.AddExtensionType(".gohtml", "text/html")
	mime.AddExtensionType(".md", "text/markdown")
}

func main() {
	var err error
	flags.DoParse()
	args := flag.Args()
	if regexp.MustCompile(`^\d+$`).MatchString(flags.Addr) {
		flags.Addr = ":" + flags.Addr
	}
	if flags.Prod {
		flags.EnableUnix = true
		flags.EnableFile = true
		flags.EnableRclone = true
		flags.EnableCurl = true
		flags.EnableExec = true
		flags.SupressError = true
		if flags.Key == "" {
			log.Fatalf("key must be set in production mode")
		}
	}
	if flags.Key == "" && (flags.OpenNormal || len(flags.OpenScopes) > 0) {
		log.Fatalf(`The "open-normal" and "open-scope" flags must be used with "key" flag`)
	}
	// key may be concated with request keytype by "\n" sep.
	// As a security prevention, forbit  "\n" in key and keytype.
	if strings.ContainsAny(flags.Key, constants.LINE_BREAKS) {
		log.Fatalf(`The "key" flag can not contains line breaks`)
	}
	flags.Rootpath, _ = normalizeUrlPath(flags.Rootpath)
	flags.KeytypeBlacklist = util.SplitCsv(flags.KeytypeBlacklistStr)
	if flags.Key != "" {
		if flags.Cipher, err = util.GetCipher(flags.Key, "", constants.KEY_PASSITER); err != nil {
			log.Fatalf("Failed to create key cipher: %v", err)
		}
	}
	if flags.Pass == "" {
		flags.Pass = flags.Key
	} else if flags.Key == "" {
		log.Fatalf(`The "pass" flag must be used with "key" flag`)
	}
	if flags.Sign && flags.Parse {
		log.Fatalf(`"sign" and "decrypt" flags are not compatible`)
	}
	if flags.Sign || flags.Parse {
		if flags.Key == "" || len(args) == 0 {
			log.Fatalf(`The "key" flag and at least one positional argument (url) must be provided`)
		}
		if flags.Sign {
			for _, targetUrl := range args {
				canonicalurl, sign, encryptedurl, entryurl, encryptedEntryurl := proxy.Generate(targetUrl, flags.Eid,
					flags.Key, flags.PublicUrl, flags.Prefix, flags.Cipher)
				var display string
				if !flags.Encrypt {
					if entryurl != "" {
						display = entryurl
					} else if flags.Keytype != "" {
						display = sign
					} else {
						display = fmt.Sprintf("%s%s=%s&%s%s=%s", flags.Prefix, proxy.KEYTYPE_STRING, flags.Keytype,
							flags.Prefix, proxy.SIGN_STRING, sign)
					}
				} else {
					if entryurl != "" {
						display = encryptedEntryurl
					} else {
						display = encryptedurl
					}
				}
				fmt.Printf("%s  %s\n", canonicalurl, display)
			}
		} else if flags.Parse {
			for _, targetUrl := range args {
				url, _, _, _, err := proxy.Parse(flags.Prefix, targetUrl, "")
				var display string
				if err != nil {
					display = fmt.Sprintf("// %v", err)
				} else {
					display = url
				}
				fmt.Printf("%s  %s\n", targetUrl, display)
			}
		}
		return
	}
	if flags.Adminpath == "" {
		flags.Adminpath = flags.Rootpath + "admin/"
	} else if flags.Adminpath == constants.NONE {
		flags.Adminpath = ""
	} else {
		flags.Adminpath, _ = normalizeUrlPath(flags.Adminpath)
	}

	// [][prefix, path, rawpath]. longest prefix first.
	// prefix & path always starts and ends with "/".
	// e.g.: ["/abc/", "/_sgp_sub_ip=//ipinfo.io/", "/_sgp_sub_ip=%2F/ipinfo.io/"] .
	var aliases = [][3]string{}
	for _, alias := range flags.Aliases {
		prefix, path, found := strings.Cut(alias, "=")
		if !found || prefix == "" || path == "" {
			log.Fatalf("invalid alias %q", alias)
		}
		prefix, _ = normalizeUrlPath(prefix)
		path, rawpath := normalizeUrlPath(path)
		if !strings.HasPrefix(path, flags.Rootpath) || !strings.HasPrefix(rawpath, flags.Rootpath) {
			log.Fatalf("invalid alias %q", alias)
		}
		aliases = append(aliases, [3]string{prefix, path, rawpath})
	}
	slices.SortFunc(aliases, func(a, b [3]string) int { return len(b[0]) - len(a[0]) })

	fmt.Printf("simplegoproxy %s starts on %s, rootpath=%s, prefix=%s, signing_enabled(key_set)=%t, supress_error=%t\n",
		version.Version, flags.Addr, flags.Rootpath, flags.Prefix, flags.Key != "", flags.SupressError)
	fmt.Printf("Supported impersonates: %s\n", strings.Join(util.Impersonates, ", "))
	fmt.Printf("Additional enabled protocols: file=%t, unix=%t, rclone=%t, curl=%t, exec=%t\n",
		flags.EnableFile, flags.EnableUnix, flags.EnableRclone, flags.EnableCurl, flags.EnableExec)
	fmt.Printf("Textual MIMEs in addition to 'text/*': %s\n", strings.Join(constants.TextualMediatypes, ", "))
	fmt.Printf("Blacklist keytypes: %v\n", flags.KeytypeBlacklist)
	if flags.Adminpath != "" {
		fmt.Printf("Admin Web UI at %q with user/pass: %s:***\n", flags.Adminpath, flags.User)
	}
	if len(flags.OpenScopes) > 0 {
		fmt.Printf("Open scopes: %v\n", flags.OpenScopes)
	}
	fmt.Printf("simplegoproxy is a open source software. See: https://github.com/sagan/simplegoproxy\n")
	if len(aliases) > 0 {
		fmt.Printf("Aliases:\n")
		for _, alias := range aliases {
			fmt.Printf("  %s => %s\n", alias[0], alias[2])
		}
	}
	fmt.Printf("\n")
	if flags.Key == "" && (flags.EnableFile || flags.EnableUnix || flags.EnableRclone || flags.EnableCurl || flags.EnableExec) {
		fmt.Printf("WARNING! Enabing non-http schemes without using signing is risky. You should only do it in local / test / sandbox env\n")
	}
	authenticator := auth.NewAuthenticator("website", false)
	nonceTree := btree.NewG[constants.Nonce](4, constants.NonceLess)
	proxyHandle := http.StripPrefix(flags.Rootpath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ProxyFunc(w, r, flags.Prefix, flags.Key, flags.KeytypeBlacklist, flags.OpenScopes, flags.OpenNormal,
			flags.SupressError, flags.Log, flags.EnableUnix, flags.EnableFile, flags.EnableRclone, flags.EnableCurl,
			flags.EnableExec, flags.RcloneBinary, flags.RcloneConfig, flags.CurlBinary, flags.Cipher, authenticator,
			nonceTree)
	}))
	var adminHandle http.Handler
	if flags.Adminpath != "" {
		adminHandle = http.StripPrefix(flags.Adminpath, admin.GetHttpHandle())
	}
	// Do not use ServeMux due to https://github.com/golang/go/issues/42244
	err = http.ListenAndServe(flags.Addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// We use fragment as a internal context variables holder. So make sure it's firstly cleared.
		r.URL.Fragment = ""
		if adminHandle != nil && strings.HasPrefix(r.URL.Path, flags.Adminpath) {
			adminHandle.ServeHTTP(w, r)
			return
		}
		for _, alias := range aliases {
			if strings.HasPrefix(r.URL.Path, alias[0]) {
				p := r.URL.Path[len(alias[0]):]
				rp := strings.TrimPrefix(r.URL.RawPath, alias[0])
				if len(rp) > 0 && len(rp) == len(r.URL.RawPath) {
					// invalid raw path
					http.NotFound(w, r)
					return
				}
				if rp == "" {
					rp = url.PathEscape(p)
				}
				r2 := new(http.Request)
				*r2 = *r
				r2.URL = new(url.URL)
				*r2.URL = *r.URL
				r2.URL.Path = alias[1] + p
				r2.URL.RawPath = alias[2] + rp
				var reqparams = url.Values{
					constants.REQ_INALIAS: []string{"1"},
					constants.REQ_RPATH:   []string{rp},
				}
				r2.URL.Fragment = reqparams.Encode()
				proxyHandle.ServeHTTP(w, r2)
				return
			}
		}
		if len(r.URL.Path) > len(flags.Rootpath) && strings.HasPrefix(r.URL.Path, flags.Rootpath) {
			proxyHandle.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	log.Fatalf("Failed to start http server: %v", err)
}

// Normalize a url path:
// 1. Unescape.
// 2. Make sure path starts and ends with "/".
func normalizeUrlPath(inputpath string) (path, rawpath string) {
	rawpath = inputpath
	if !strings.HasPrefix(rawpath, "/") {
		rawpath = "/" + rawpath
	}
	if !strings.HasSuffix(rawpath, "/") {
		rawpath += "/"
	}
	if p, err := url.PathUnescape(rawpath); err == nil {
		path = p
	} else {
		path = rawpath
	}
	return path, rawpath
}
