package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/sagan/simplegoproxy/admin"
	"github.com/sagan/simplegoproxy/flags"
	"github.com/sagan/simplegoproxy/proxy"
	"github.com/sagan/simplegoproxy/util"
	"github.com/sagan/simplegoproxy/version"
)

func main() {
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
		if envValue := os.Getenv(strings.ToUpper(f.Name)); envValue != "" {
			err := f.Value.Set(envValue)
			if err != nil {
				log.Fatalf("Failed to set %s flag to %s from env: %v", f.Name, envValue, err)
			}
		}
	})
	if !strings.HasPrefix(flags.Rootpath, "/") {
		flags.Rootpath = "/" + flags.Rootpath
	}
	if !strings.HasSuffix(flags.Rootpath, "/") {
		flags.Rootpath += "/"
	}
	flags.KeytypeBlacklist = util.SplitCsv(flags.KeytypeBlacklistStr)
	if flags.Pass == "" {
		flags.Pass = flags.Key
	} else if flags.Key == "" {
		log.Fatalf(`The "pass" flag must be used with "key" flag`)
	}

	if flags.Sign {
		if flags.Key == "" || len(args) == 0 {
			log.Fatalf("The signkey flag and at least one argument (url) must be provided")
		}
		for _, targetUrl := range args {
			canonicalurl, sign, entryurl := proxy.Generate(targetUrl, flags.Key, flags.PublicUrl, flags.Prefix)
			if entryurl != "" {
				fmt.Printf("%s  %s\n", canonicalurl, entryurl)
			} else {
				if flags.Keytype != "" {
					fmt.Printf("%s  %s%s=%s  %s\n", canonicalurl, flags.Prefix, proxy.KEYTYPE_STRING, flags.Keytype, sign)
				} else {
					fmt.Printf("%s  %s\n", canonicalurl, sign)
				}
			}
		}
		return
	}

	adminPath := flags.Rootpath + "admin/"
	fmt.Printf("simplegoproxy %s start port=%d, rootpath=%s, prefix=%s, key=%s\n",
		version.Version, flags.Port, flags.Rootpath, flags.Prefix, flags.Key)
	fmt.Printf("Supported impersonates: %s\n", strings.Join(util.Impersonates, ", "))
	fmt.Printf("Additional enabled protocols: file=%t, unix=%t, rclone=%t\n", flags.File, flags.Unix, flags.Rclone)
	fmt.Printf("Textual MIMEs in addition to 'text/*': %s\n", strings.Join(proxy.TEXTUAL_MIMES, ", "))
	fmt.Printf("Blacklist keytypes: %v\n", flags.KeytypeBlacklist)
	fmt.Printf("Admin Web UI at %q with user/pass: %s:%s\n", adminPath, flags.User, flags.Pass)

	proxyHandle := http.StripPrefix(flags.Rootpath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ProxyFunc(w, r, flags.Prefix, flags.Key, flags.KeytypeBlacklist, flags.Log, flags.Unix, flags.File,
			flags.Rclone, flags.RcloneBinary, flags.RcloneConfig)
	}))
	adminHandle := http.StripPrefix(adminPath, admin.GetHttpHandle())
	// Do not use ServeMux due to https://github.com/golang/go/issues/42244
	err := http.ListenAndServe(fmt.Sprintf(":%d", flags.Port), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
