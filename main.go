package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/sagan/simplegoproxy/admin"
	"github.com/sagan/simplegoproxy/constants"
	"github.com/sagan/simplegoproxy/flags"
	"github.com/sagan/simplegoproxy/proxy"
	"github.com/sagan/simplegoproxy/util"
	"github.com/sagan/simplegoproxy/version"
)

func main() {
	var err error
	flag.Parse()
	args := flag.Args()
	flagsSet := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		flagsSet[f.Name] = true
	})
	flag.VisitAll(func(f *flag.Flag) {
		if flagsSet[f.Name] {
			return
		}
		envname := constants.SGP_ENV_PREFIX + strings.ReplaceAll(strings.ToUpper(f.Name), "-", "_")
		if envValue := os.Getenv(envname); envValue != "" {
			err := f.Value.Set(envValue)
			if err != nil {
				log.Fatalf("Failed to set %s flag to %q from env %s: %v", f.Name, envValue, envname, err)
			}
		}
	})
	if regexp.MustCompile(`^\d+$`).MatchString(flags.Addr) {
		flags.Addr = ":" + flags.Addr
	}
	if flags.EnableAll {
		flags.EnableUnix = true
		flags.EnableFile = true
		flags.EnableRclone = true
		flags.EnableCurl = true
		flags.EnableExec = true
	}
	if flags.OpenHttp {
		flags.OpenScopes = append(flags.OpenScopes, "*://*")
	}
	if flags.Key == "" && len(flags.OpenScopes) > 0 {
		log.Fatalf(`The "open-http" and "open-scope" flags must be used with "key" flag`)
	}
	if !strings.HasPrefix(flags.Rootpath, "/") {
		flags.Rootpath = "/" + flags.Rootpath
	}
	if !strings.HasSuffix(flags.Rootpath, "/") {
		flags.Rootpath += "/"
	}
	flags.KeytypeBlacklist = util.SplitCsv(flags.KeytypeBlacklistStr)
	if flags.Key != "" {
		if flags.Cipher, err = util.GetDeterministicCipher(flags.Key); err != nil {
			log.Fatalf("Failed to create key cipher: %v", err)
		}
	}
	if flags.Pass == "" {
		flags.Pass = flags.Key
	} else if flags.Key == "" {
		log.Fatalf(`The "pass" flag must be used with "key" flag`)
	}
	if flags.Sign && flags.Decrypt {
		log.Fatalf(`"sign" and "decrypt" flags are not compatible`)
	}
	if flags.Sign || flags.Decrypt {
		if flags.Key == "" || len(args) == 0 {
			log.Fatalf(`The "key" flag and at least one positional argument (url) must be provided`)
		}
		if flags.Sign {
			for _, targetUrl := range args {
				canonicalurl, sign, encryptedurl, entryurl, encryptedEntryurl := proxy.Generate(targetUrl, flags.Key,
					flags.PublicUrl, flags.Prefix, flags.Cipher)
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
		} else if flags.Decrypt {
			for _, targetUrl := range args {
				url, _, err := proxy.Decrypt(targetUrl, "")
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

	adminPath := flags.Rootpath + "admin/"
	fmt.Printf("simplegoproxy %s starts on %s, rootpath=%s, prefix=%s, signing_enabled=%t\n",
		version.Version, flags.Addr, flags.Rootpath, flags.Prefix, flags.Key != "")
	fmt.Printf("Supported impersonates: %s\n", strings.Join(util.Impersonates, ", "))
	fmt.Printf("Additional enabled protocols: file=%t, unix=%t, rclone=%t, curl=%t, exec=%t\n",
		flags.EnableFile, flags.EnableUnix, flags.EnableRclone, flags.EnableCurl, flags.EnableExec)
	fmt.Printf("Textual MIMEs in addition to 'text/*': %s\n", strings.Join(proxy.TEXTUAL_MIMES, ", "))
	fmt.Printf("Blacklist keytypes: %v\n", flags.KeytypeBlacklist)
	fmt.Printf("Admin Web UI at %q with user/pass: %s:***\n", adminPath, flags.User)
	if len(flags.OpenScopes) > 0 {
		fmt.Printf("Open scopes: %v\n", flags.OpenScopes)
	}
	fmt.Printf("simplegoproxy is a open source software. See: https://github.com/sagan/simplegoproxy\n")
	fmt.Printf("\n")
	if flags.Key == "" && (flags.EnableFile || flags.EnableUnix || flags.EnableRclone || flags.EnableCurl || flags.EnableExec) {
		fmt.Printf("WARNING! Enabing non-http schemes without using signing is risky. You should only do it in local / test / sandbox env\n")
	}

	proxyHandle := http.StripPrefix(flags.Rootpath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ProxyFunc(w, r, flags.Prefix, flags.Key, flags.KeytypeBlacklist, flags.OpenScopes, flags.SupressError,
			flags.Log, flags.EnableUnix, flags.EnableFile, flags.EnableRclone, flags.EnableCurl, flags.EnableExec,
			flags.RcloneBinary, flags.RcloneConfig, flags.CurlBinary, flags.Cipher)
	}))
	adminHandle := http.StripPrefix(adminPath, admin.GetHttpHandle())
	// Do not use ServeMux due to https://github.com/golang/go/issues/42244
	err = http.ListenAndServe(flags.Addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, adminPath) {
			adminHandle.ServeHTTP(w, r)
			return
		} else if strings.HasPrefix(r.URL.Path, flags.Rootpath) {
			if r.URL.Path == flags.Rootpath {
				http.Redirect(w, r, flags.Rootpath+"admin/", http.StatusTemporaryRedirect)
				return
			}
			proxyHandle.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	log.Fatalf("Failed to start http server: %v", err)
}
