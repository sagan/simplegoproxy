package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/sagan/simplegoproxy/util"
	"github.com/sagan/simplegoproxy/version"
)

var (
	port     int
	doSign   bool
	rootpath string
	prefix   string
	key      string
)

func main() {
	flag.IntVar(&port, "port", 3000, "Http listening port")
	flag.BoolVar(&doSign, "sign", false, `Calculate the sign of target url and output result. The "key" flag need to be set. Args are url(s)`)
	flag.StringVar(&rootpath, "rootpath", "/", "Root path (with leading and trailing slash)")
	flag.StringVar(&prefix, "prefix", "_sgp_", "Prefix of settings in query parameters")
	flag.StringVar(&key, "key", "", "The sign key. If set, all requests must be signed using HMAC(key, 'sha-256', payload=url), providing calculated MAC (hex string) in _sgp_sign")
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
	if !strings.HasPrefix(rootpath, "/") {
		rootpath = "/" + rootpath
	}
	if !strings.HasSuffix(rootpath, "/") {
		rootpath += "/"
	}

	if doSign {
		if key == "" || len(args) == 0 {
			log.Fatalf("The signkey flag and at least one argument (url) must be provided")
		}
		mac := hmac.New(sha256.New, []byte(key))
		for _, targetUrl := range args {
			urlObj, err := url.Parse(targetUrl)
			// use the full canonical url
			if err == nil {
				if urlObj.Scheme == "" {
					urlObj.Scheme = "https"
				}
				if urlObj.Host != "" && urlObj.Path == "" {
					urlObj.Path = "/"
				}
				urlQuery := urlObj.Query()
				urlQuery.Del(prefix + SIGN_STRING)
				urlObj.RawQuery = urlQuery.Encode() // query key sorted
				targetUrl = urlObj.String()
			}
			mac.Write([]byte(targetUrl))
			messageMac := mac.Sum(nil)
			fmt.Printf("%s  %s\n", hex.EncodeToString(messageMac), targetUrl)
			mac.Reset()
		}
		return
	}

	fmt.Printf("simplegoproxy %s start port=%d, rootpath=%s, key=%s\n", version.Version, port, rootpath, key)
	fmt.Printf("Supported impersonates: %s\n", strings.Join(util.Impersonates, ", "))
	fmt.Printf("Textual MIMEs in addition to 'text/*': %s\n", strings.Join(TEXTUAL_MIMES, ", "))

	proxyHandle := http.StripPrefix(rootpath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyFunc(w, r, prefix, key)
	}))
	// Do not use ServeMux due to https://github.com/golang/go/issues/42244
	err := http.ListenAndServe(fmt.Sprintf(":%d", port), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, rootpath) {
			proxyHandle.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	log.Fatalf("Failed to start http server: %v", err)
}
