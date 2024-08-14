package admin

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/sagan/simplegoproxy/flags"
	"github.com/sagan/simplegoproxy/proxy"
	"github.com/sagan/simplegoproxy/util"
	"github.com/sagan/simplegoproxy/version"
)

//go:embed dist
var Webfs embed.FS

type ApiFunc func(params url.Values) (data any, err error)

var ApiFuncs = map[string]ApiFunc{
	"generate": Generate,
}

var GetHttpHandle = func() http.Handler {
	root, _ := fs.Sub(Webfs, "dist")
	fileServer := http.FileServer(http.FS(root))
	indexHtml, _ := Webfs.ReadFile("dist/index.html")
	indexHtmlStr := string(indexHtml)
	variables := map[string]string{
		"ROOTPATH": flags.Rootpath,
		"PREFIX":   flags.Prefix,
		"ENV":      "production",
		"VERSION":  version.Version,
	}
	variableRegex := regexp.MustCompile(`".*?"; //__([A-Z][_A-Z0-9]*?)__`)
	indexHtmlStr = variableRegex.ReplaceAllStringFunc(indexHtmlStr, func(s string) string {
		i := strings.Index(s, "__")
		j := strings.LastIndex(s, "__")
		variable := s[i+2 : j]
		if value, ok := variables[variable]; ok {
			return fmt.Sprintf(`%q; //%s`, value, s[j+2:])
		}
		return s
	})
	indexHtml = []byte(indexHtmlStr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="website"`)
		if flags.Cors {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		if flags.Pass != "" {
			username, password, ok := r.BasicAuth()
			if !ok || username != flags.User || password != flags.Pass {
				w.WriteHeader(401)
				w.Write([]byte("Unauthorized"))
				return
			}
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		f, err := root.Open(path)
		if err == nil {
			defer f.Close()
		}
		if path == "api" {
			apiHandler(w, r)
			return
		}
		if path == "" || os.IsNotExist(err) {
			w.Write(indexHtml)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

var apiHandler = func(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodOptions && r.Method != http.MethodPost {
		w.WriteHeader(400)
		return
	}
	r.ParseForm()
	w.Header().Add("Content-Type", "application/json")
	if funcName := r.Form.Get("func"); funcName == "" {
		w.WriteHeader(404)
	} else if apiFunc := ApiFuncs[funcName]; apiFunc == nil {
		w.WriteHeader(404)
	} else if data, err := apiFunc(r.Form); err != nil {
		w.WriteHeader(500)
		util.PrintJson(w, err.Error())
	} else {
		util.PrintJson(w, data)
	}
}

func Generate(params url.Values) (data any, err error) {
	if !params.Has("url") {
		return nil, fmt.Errorf("invalid parameters")
	}
	canonicalurl, sign, entryurl := proxy.Generate(params.Get("url"), flags.Key, params.Get("publicurl"), flags.Prefix)
	data = map[string]any{
		"url":      canonicalurl,
		"entryurl": entryurl,
		"sign":     sign,
	}
	return data, nil
}
