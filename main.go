package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/sagan/simplegoproxy/util"
	"github.com/sagan/simplegoproxy/version"
)

var (
	port     int
	rootpath string
	prefix   string
)

func main() {
	flag.IntVar(&port, "port", 3000, "Http listening port")
	flag.StringVar(&rootpath, "rootpath", "/", "Root path (with leading and trailing slash)")
	flag.StringVar(&prefix, "prefix", "_sgp_", "Prefix of settings in query parameters")
	flag.Parse()
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
	fmt.Printf("simplegoproxy %s start port=%d, rootpath=%s\n", version.Version, port, rootpath)
	fmt.Printf("Supported impersonates: %s\n", strings.Join(util.Impersonates, ", "))
	fmt.Printf("Textual MIMEs in addition to 'text/*': %s\n", strings.Join(TEXTUAL_MIMES, ", "))

	proxyHandle := http.StripPrefix(rootpath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyFunc(w, r, prefix)
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
