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
	"parse":    Parse,
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
	marker := "; //__"
	endmarker := "__"
	variableRegex := regexp.MustCompile(`".*?"` + regexp.QuoteMeta(marker) +
		`([A-Z][_A-Z0-9]*?)` + regexp.QuoteMeta(endmarker))
	indexHtmlStr = variableRegex.ReplaceAllStringFunc(indexHtmlStr, func(s string) string {
		i := strings.Index(s, marker)
		j := strings.LastIndex(s, endmarker)
		variable := s[i+len(marker) : j]
		if value, ok := variables[variable]; ok {
			return fmt.Sprintf(`%q%s`, value, s[i:])
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
	canonicalurl, sign, _, entryurl, encryptedEntryurl := proxy.Generate(params.Get("url"), params.Get("eid"),
		flags.Key, params.Get("publicurl"), flags.Prefix, flags.Cipher)
	data = map[string]any{
		"url":                canonicalurl,
		"entryurl":           entryurl,
		"encrypted_entryurl": encryptedEntryurl,
		"sign":               sign,
	}
	return data, nil
}

func Parse(params url.Values) (any, error) {
	url, encrypted_entryurl, entryurl, eid, err := proxy.Decrypt(flags.Prefix, params.Get("url"), params.Get("publicurl"))
	if err != nil {
		return nil, err
	}
	data := map[string]any{
		"url":                url,
		"eid":                eid,
		"entryurl":           entryurl,
		"encrypted_entryurl": encrypted_entryurl,
	}
	return data, nil
}
