package util

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/Noooste/azuretls-client"
	"github.com/google/shlex"
	"github.com/jxskiss/base62"
	"github.com/pelletier/go-toml/v2"
	range_parser "github.com/quantumsheep/range-parser"
	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/yaml.v3"

	"github.com/sagan/simplegoproxy/constants"
)

type NetRequest struct {
	Req          *http.Request
	Impersonate  string
	Insecure     bool
	Timeout      int64
	Proxy        string
	Norf         bool
	RcloneBinary string
	RcloneConfig string
	CurlBinary   string
	Debug        bool
	Username     string
	Password     string
	DoLog        bool
	Params       url.Values // original all "_sgp" params
}

type ImpersonateProfile struct {
	Name string
	// "chrome", "firefox", "opera", "safari", "edge", "ios", "android"
	Navigator     string
	Ja3           string
	H2fingerprint string
	Headers       [][]string // use "\n" as placeholder for order; use "" (empty) to delete a header
	Comment       string
}

type rcloneLsjsonItem struct {
	IsDir   bool          `json:"IsDir,omitempty"`
	ModTime TimestampTime `json:"ModTime,omitempty"` // "2017-05-31T16:15:57.034468261+01:00"
	Name    string        `json:"Name,omitempty"`    // "file.txt"
	Path    string        `json:"Path,omitempty"`    //"full/path/file.txt". Relative to <root_path>
	Size    int64         `json:"Size,omitempty"`    // -1 for dir
}

const (
	HTTP_HEADER_PLACEHOLDER = "\n"
)

var (
	// all supported impersonate names
	Impersonates []string
)

func init() {
	for key := range ImpersonateProfiles {
		Impersonates = append(Impersonates, key)
	}
	slices.Sort(Impersonates)
}

var ImpersonateProfiles = map[string]*ImpersonateProfile{
	"chrome120": {
		Navigator:     "chrome",
		Comment:       "Chrome 120 on Windows 11 x64 en-US",
		Ja3:           "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-45-11-65037-18-5-51-0-23-27-43-16-10-35-17513-13,29-23-24,0",
		H2fingerprint: "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p",
		Headers: [][]string{
			{"Cache-Control", "max-age=0"},
			{"Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`},
			{"Sec-Ch-Ua-Mobile", `?0`},
			{"Sec-Ch-Ua-Platform", `"Windows"`},
			{"Upgrade-Insecure-Requests", "1"},
			{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
			{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"Sec-Fetch-Site", `none`},
			{"Sec-Fetch-Mode", `navigate`},
			{"Sec-Fetch-User", `?1`},
			{"Sec-Fetch-Dest", `document`},
			{"Accept-Encoding", "gzip, deflate, br"},
			{"Accept-Language", "en-US,en;q=0.9"},
			{"Cookie", HTTP_HEADER_PLACEHOLDER},
		},
	},
	"chrome122": {
		Name:          "chrome122",
		Navigator:     "chrome",
		Comment:       "Chrome 122 on Windows 11 x64 en-US",
		Ja3:           "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-13-27-16-51-65281-45-5-17513-0-35-43-65037-11-18-10,29-23-24,0",
		H2fingerprint: "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p",
		Headers: [][]string{
			{"Cache-Control", "max-age=0"},
			{"Sec-Ch-Ua", `"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"`},
			{"Sec-Ch-Ua-Mobile", `?0`},
			{"Sec-Ch-Ua-Platform", `"Windows"`},
			{"Upgrade-Insecure-Requests", "1"},
			{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"},
			{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"Sec-Fetch-Site", `none`},
			{"Sec-Fetch-Mode", `navigate`},
			{"Sec-Fetch-User", `?1`},
			{"Sec-Fetch-Dest", `document`},
			{"Accept-Encoding", "gzip, deflate, br, zstd"},
			{"Accept-Language", "en-US,en;q=0.9"},
			{"Cookie", HTTP_HEADER_PLACEHOLDER},
		},
	},
	"firefox121": {
		Navigator: "firefox",
		Comment:   "Firefox 121 on Windows 11 x64 en-US",
		// Ja3:           "772,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0",
		// utls do not support TLS 34 delegated_credentials (34) (IANA) extension at this time.
		// see https://github.com/refraction-networking/utls/issues/274
		Ja3:           "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-51-43-13-45-28-65037,29-23-24-25-256-257,0",
		H2fingerprint: "1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
		Headers: [][]string{
			{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"},
			{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
			{"Accept-Language", "en-US,en;q=0.5"},
			{"Accept-Encoding", "gzip, deflate, br"},
			{"Cookie", HTTP_HEADER_PLACEHOLDER},
			{"Upgrade-Insecure-Requests", "1"},
			{"Sec-Fetch-Dest", `document`},
			{"Sec-Fetch-Mode", `navigate`},
			{"Sec-Fetch-Site", `none`},
			{"Sec-Fetch-User", `?1`},
			{"te", "trailers"},
		},
	},
}

func fetchUnix(req *http.Request) (*http.Response, error) {
	// req.URL: "unix:///path/to/socket:resource_url" .
	// Host is empty and path is a ":" splitted two parts.
	uncPath, resourceUrl, found := strings.Cut(req.URL.Path, ":")
	if !found {
		return nil, fmt.Errorf(`invalid unix domain socket url. format: "unix:///path/to/socket:resource_url"`)
	}
	httpc := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", uncPath)
			},
		},
	}
	resourceUrlObj, err := url.Parse(resourceUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse unix domain socket resource url: %w", err)
	}
	dummyUrl := "http://unix/" + strings.TrimPrefix(resourceUrlObj.Path, "/")
	if req.URL.RawQuery != "" {
		dummyUrl += "?" + req.URL.RawQuery
	}
	return httpc.Get(dummyUrl) // dummy http protocol url prefix
}

func fetchFile(req *http.Request) (*http.Response, error) {
	localfilepath := ParseLocalFileUrlFilepath(req.URL)
	if localfilepath == "" {
		return nil, fmt.Errorf("invalid file url")
	}
	stat, err := os.Stat(localfilepath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file %q: %w", localfilepath, err)
	}
	if stat.Mode().IsDir() {
		tpl, err := template.New("template").Parse(constants.DIR_INDEX_HTML)
		if err != nil {
			return nil, fmt.Errorf("failed to compile dir index template: %w", err)
		}
		entries, err := os.ReadDir(localfilepath)
		if err != nil {
			return nil, fmt.Errorf("failed to read dir: %w", err)
		}
		files := []map[string]any{}
		for _, entry := range entries {
			file := map[string]any{
				"Name":    entry.Name(),
				"IsDir":   entry.IsDir(),
				"ModTime": int64(0),
				"Size":    int64(-1),
			}
			if info, err := entry.Info(); err == nil {
				file["ModTime"] = info.ModTime().Unix()
				if entry.Type().IsRegular() {
					file["Size"] = info.Size()
				}
			}
			files = append(files, file)
		}
		buf := &bytes.Buffer{}
		err = tpl.Execute(buf, map[string]any{
			"Dir":    localfilepath,
			"IsRoot": IsRootPath(localfilepath),
			"Files":  files,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to render dir template: %w", err)
		}
		res := &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":   []string{"text/html"},
				"Content-Length": []string{fmt.Sprint(buf.Len())},
			},
			Body: io.NopCloser(buf),
		}
		return res, nil
	}
	file, err := os.Open(localfilepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %q: %v", localfilepath, err)
	}
	contentType := FileContentType(localfilepath)
	res := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Accept-Ranges": []string{"bytes"},
			"Content-Type":  []string{contentType},
			"Last-Modified": []string{stat.ModTime().UTC().Format(http.TimeFormat)},
		},
	}
	if lastModified := req.Header.Get("If-Modified-Since"); lastModified != "" {
		t, err := http.ParseTime(lastModified)
		if err == nil && stat.ModTime().Unix() <= t.Unix() {
			res.StatusCode = http.StatusNotModified
			return res, nil
		}
	}
	// HTTP Range Request.
	// Reference: https://www.zeng.dev/post/2023-http-range-and-play-mp4-in-browser/ .
	if req.Header.Get("Range") != "" {
		rangesFile, err := NewRangesFile(file, contentType, stat.Size(), req.Header.Get("Range"))
		if err != nil {
			file.Close()
			return errResponseInvalidRange(stat.Size()), nil
		}
		rangesFile.SetHeader(res.Header)
		res.StatusCode = http.StatusPartialContent
		res.Body = rangesFile
	} else {
		res.Header.Set("Content-Length", fmt.Sprint(stat.Size()))
		res.Body = file
	}
	return res, nil
}

func fetchHttp(netreq *NetRequest) (*http.Response, error) {
	req := netreq.Req
	reqUrl := req.URL.String()
	if netreq.Impersonate == "" {
		var httpClient *http.Client
		if netreq.Insecure || netreq.Norf || netreq.Proxy != "" || netreq.Timeout > 0 {
			httpClient = &http.Client{
				Timeout: time.Duration(netreq.Timeout) * time.Second,
			}
			if netreq.Insecure || netreq.Proxy != "" {
				var proxyFunc func(*http.Request) (*url.URL, error)
				if netreq.Proxy != "" {
					proxyUrl, err := url.Parse(netreq.Proxy)
					if err != nil {
						return nil, fmt.Errorf("failed to parse proxy %s: %v", netreq.Proxy, err)
					}
					proxyFunc = http.ProxyURL(proxyUrl)
				} else {
					proxyFunc = http.ProxyFromEnvironment
				}
				httpClient.Transport = &http.Transport{
					Proxy:           proxyFunc,
					TLSClientConfig: &tls.Config{InsecureSkipVerify: netreq.Insecure},
				}
			}
			if netreq.Norf {
				httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				}
			}
		} else {
			httpClient = http.DefaultClient
		}
		return httpClient.Do(req)
	}
	ip := ImpersonateProfiles[netreq.Impersonate]
	if ip == nil {
		return nil, fmt.Errorf("impersonate target %s not supported", netreq.Impersonate)
	}
	session := azuretls.NewSession()
	session.SetContext(req.Context())
	if netreq.Timeout > 0 {
		session.SetTimeout(time.Duration(netreq.Timeout) * time.Second)
	}
	if ip.Ja3 != "" {
		if err := session.ApplyJa3(ip.Ja3, ip.Navigator); err != nil {
			return nil, fmt.Errorf("failed to set ja3: %w", err)
		}
	}
	if ip.H2fingerprint != "" {
		if err := session.ApplyHTTP2(ip.H2fingerprint); err != nil {
			return nil, fmt.Errorf("failed to set h2 finterprint: %w", err)
		}
	}
	if netreq.Proxy == "" {
		netreq.Proxy = ParseProxyFromEnv(reqUrl)
	}
	if netreq.Proxy != "" {
		if err := session.SetProxy(netreq.Proxy); err != nil {
			return nil, fmt.Errorf("failed to set proxy: %w", err)
		}
	}
	if netreq.Insecure {
		session.InsecureSkipVerify = true
	}

	allHeaders := [][]string{}
	effectiveHeaders := [][]string{}
	headerIndexs := map[string]int{}
	allHeaders = append(allHeaders, ip.Headers...)
	for key := range req.Header {
		for _, value := range req.Header[key] {
			allHeaders = append(allHeaders, []string{key, value})
		}
	}
	for _, header := range allHeaders {
		headerLowerCase := strings.ToLower(header[0])
		if index, ok := headerIndexs[headerLowerCase]; ok {
			effectiveHeaders[index] = []string{header[0], header[1]}
			if header[1] == "" {
				delete(headerIndexs, headerLowerCase)
			}
		} else if header[1] != "" {
			effectiveHeaders = append(effectiveHeaders, []string{header[0], header[1]})
			headerIndexs[headerLowerCase] = len(effectiveHeaders) - 1
		}
	}
	orderedHeaders := azuretls.OrderedHeaders{}
	for _, header := range effectiveHeaders {
		if header[1] == "" || header[1] == HTTP_HEADER_PLACEHOLDER {
			continue
		}
		orderedHeaders = append(orderedHeaders, header)
	}

	res, err := session.Do(&azuretls.Request{
		Method:           req.Method,
		Url:              reqUrl,
		IgnoreBody:       true,
		DisableRedirects: netreq.Norf,
	}, orderedHeaders)
	if err != nil {
		if _, ok := err.(net.Error); ok {
			return nil, fmt.Errorf("failed to fetch url: <network error>: %w", err)
		}
		return nil, fmt.Errorf("failed to fetch url: %w", err)
	}
	// For some reason, azuretls returns "content-encoding: gzip/br" header AND non-comprerss plain body for some url.
	// e.g.: whoami ( https://github.com/traefik/whoami ) page.
	if res.Header.Get("Content-Encoding") != "" {
		res.Header.Del("Content-Encoding")
		res.Header.Del("Content-Length")
	}
	return &http.Response{
		StatusCode: res.StatusCode,
		Header:     http.Header(res.Header),
		Body:       res.RawBody,
	}, nil
}

// If timeout > 0, it will wait for timeout seconds before returning process stdout as body.
// If the child process exits before timeout with non-zero exit code, it returns error.
// If the child process exits after timeout with none-zero exit code, there's no way to notify it to caller.
// If debug is true, the body is the combined stdout and stderr of child process, instead of stdout only,
// and it will output the process's exit code after the main stream ends.
// At least one of returned body and err will be non-nil; It may return both non-nil body and err.
// The caller is responsible to close the returned body, if not nil.
func runProcess(ctx context.Context, binary string, args []string, timeout int64,
	debug bool) (body io.ReadCloser, err error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	var stdout, stderr io.ReadCloser
	var combineReader, combineWriter *os.File
	if debug {
		combineReader, combineWriter, err = os.Pipe()
		if err != nil {
			return nil, fmt.Errorf("failed to create combined pipe: %w", err)
		}
		cmd.Stdout = combineWriter
		cmd.Stderr = combineWriter
	} else {
		stdout, err = cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to pipe process stdout: %w", err)
		}
		stderr, err = cmd.StderrPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to pipe process stderr: %w", err)
		}
	}
	if err := cmd.Start(); err != nil {
		if debug {
			combineReader.Close()
			combineWriter.Close()
		}
		return nil, fmt.Errorf("failed to exec process: %w", err)
	}
	if debug {
		combineWriter.Close()
	}
	var suffix *onetimeBuffer
	if debug || timeout > 0 {
		suffix = NewOnetimeBuffer()
		var cmderr error
		donech := make(chan struct{})
		go func() {
			//cmd.Wait will close pipes so do not use it.
			state, err := cmd.Process.Wait()
			if err == nil {
				if !state.Success() {
					cmderr = &exec.ExitError{ProcessState: state}
				}
				if debug {
					suffix.WriteOnce([]byte(fmt.Sprintf("\nprocess exit %d\n", state.ExitCode())))
				} else {
					suffix.WriteOnce(nil)
				}
			}
			select {
			case donech <- struct{}{}:
			default:
			}
			close(donech)
		}()
		cmddone := false
		if timeout > 0 {
			select {
			case <-donech:
				cmddone = true
			case <-time.After(time.Second * time.Duration(timeout)):
			}
			if cmddone && cmderr != nil {
				err = fmt.Errorf("process err: %w", cmderr)
				if debug {
					return ReadCloserWithAddition(combineReader, nil, suffix), err
				} else {
					stderr.Close()
					return stdout, err
				}
			}
		}
	}
	if debug {
		return ReadCloserWithAddition(combineReader, nil, suffix), nil
	} else {
		stderr.Close()
		return stdout, nil
	}
}

// Use curl to fetch url
func fetchCurl(netreq *NetRequest) (res *http.Response, err error) {
	req := netreq.Req
	curl := netreq.CurlBinary
	if curl == "" {
		curl = "curl"
	}
	var args []string
	if netreq.Username != "" {
		args = append(args, "--user", netreq.Username+":"+netreq.Password)
	}
	if netreq.Insecure {
		args = append(args, "--insecure")
	}
	if netreq.Proxy != "" {
		args = append(args, "--proxy", netreq.Proxy)
	}
	if req.Method != http.MethodGet {
		args = append(args, "--request", req.Method)
	}
	if req.Body != nil {
		data, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		if len(data) > 0 {
			args = append(args, "--data-raw", string(data))
		}
	}
	for key, values := range req.Header {
		for _, value := range values {
			args = append(args, "--header", fmt.Sprintf("%s: %s", key, value))
		}
	}
	if curlargs, err := getArgs(netreq.Params); err != nil {
		return nil, err
	} else {
		args = append(args, curlargs...)
	}
	args = append(args, req.URL.String())
	if netreq.DoLog {
		log.Printf("Run %s %v", curl, args)
	}
	body, err := runProcess(req.Context(), curl, args, netreq.Timeout, netreq.Debug)
	return processResponse(body, err, FileContentType(req.URL.Path)), nil
}

// "exec:///path/to/binary?arg=a&arg=b" => "/path/to/binary a b"
func fetchExec(netreq *NetRequest) (res *http.Response, err error) {
	localfilepath := ParseExecUrlFilepath(netreq.Req.URL)
	if localfilepath == "" {
		return nil, fmt.Errorf("invalid file url")
	}
	queryParams := netreq.Req.URL.Query()
	args, err := getArgs(queryParams)
	if err != nil {
		return nil, err
	}
	if netreq.DoLog {
		log.Printf("Run %s %v", localfilepath, args)
	}
	body, err := runProcess(netreq.Req.Context(), localfilepath, args, netreq.Timeout, netreq.Debug)
	res = processResponse(body, err, "")
	if res.StatusCode == http.StatusOK && !netreq.Debug {
		if typ := queryParams.Get("type"); typ != "" {
			res.Header.Set("Content-Type", ContentType(typ))
		}
	}
	return res, nil
}

// https://rclone.org/commands/rclone_cat/
func fetchRclone(netreq *NetRequest) (*http.Response, error) {
	req := netreq.Req
	rcloneBinary := netreq.RcloneBinary
	if rcloneBinary == "" {
		rcloneBinary = "rclone"
	}
	if req.URL.Host == "" {
		return nil, fmt.Errorf("rclone remote name is empty")
	}
	// req.URL: "rclone://remote/path/to/file"
	// For most rclone remotes, the canonical root path is "", not "/".
	// However, here we use a leading "/" in path for compatibility with some remotes.
	// rclone will internally normalize path.
	var remotePathname string
	if req.URL.Path == "" {
		remotePathname = "/"
	} else {
		remotePathname = path.Clean(req.URL.Path)
	}
	remotePath := req.URL.Host + ":" + remotePathname

	statargs := []string{"lsjson", "--stat", remotePath}
	if netreq.RcloneConfig != "" {
		statargs = append(statargs, "--config", netreq.RcloneConfig)
	}
	statcmd := exec.CommandContext(req.Context(), rcloneBinary, statargs...)
	statstr, err := statcmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get rclone item stat [%v]: %w", statargs, err)
	}
	var stat *rcloneLsjsonItem
	if err = json.Unmarshal(statstr, &stat); err != nil {
		return nil, fmt.Errorf("failed to parse rclone stat: %w", err)
	}

	if stat.IsDir {
		args := []string{"lsjson", remotePath}
		if netreq.RcloneConfig != "" {
			args = append(args, "--config", netreq.RcloneConfig)
		}
		cmd := exec.CommandContext(req.Context(), rcloneBinary, args...)
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to list rclone dir [%v]: %w", args, err)
		}
		var entries []*rcloneLsjsonItem
		if err = json.Unmarshal(out, &entries); err != nil {
			return nil, fmt.Errorf("failed to parse rclone lsjson: %w", err)
		}
		tpl, err := template.New("template").Parse(constants.DIR_INDEX_HTML)
		if err != nil {
			return nil, fmt.Errorf("failed to compile dir index template: %w", err)
		}
		buf := &bytes.Buffer{}
		err = tpl.Execute(buf, map[string]any{
			"Dir":    remotePath,
			"IsRoot": IsRootPath(remotePathname),
			"Files":  entries,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to render dir template: %w", err)
		}
		res := &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":   []string{"text/html"},
				"Content-Length": []string{fmt.Sprint(buf.Len())},
			},
			Body: io.NopCloser(buf),
		}
		return res, nil
	}

	res := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":  []string{FileContentType(remotePath)},
			"Last-Modified": []string{time.Time(stat.ModTime).UTC().Format(http.TimeFormat)},
			"Accept-Ranges": []string{"bytes"},
		},
	}
	if lastModified := req.Header.Get("If-Modified-Since"); lastModified != "" {
		t, err := http.ParseTime(lastModified)
		if err == nil && time.Time(stat.ModTime).Unix() <= t.Unix() {
			res.StatusCode = http.StatusNotModified
			return res, nil
		}
	}
	args := []string{"cat", remotePath}
	if netreq.RcloneConfig != "" {
		args = append(args, "--config", netreq.RcloneConfig)
	}
	for key, values := range req.URL.Query() {
		if strings.HasPrefix(key, "_") || strings.HasPrefix(key, "$") || strings.HasPrefix(key, ".") {
			continue
		}
		key = "--" + key
		for _, value := range values {
			if value != "" {
				args = append(args, key, value)
			} else {
				args = append(args, key)
			}
		}
	}
	if req.Header.Get("Range") != "" {
		ranges, err := range_parser.Parse(stat.Size, req.Header.Get("Range"))
		if err != nil || len(ranges) != 1 {
			return errResponseInvalidRange(stat.Size), nil
		}
		args = append(args, "--offset", fmt.Sprint(ranges[0].Start), "--count", fmt.Sprint(ranges[0].End-ranges[0].Start+1))
		res.StatusCode = http.StatusPartialContent
		res.Header.Set("Content-Length", fmt.Sprint(ranges[0].End-ranges[0].Start+1))
		res.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", ranges[0].Start, ranges[0].End, stat.Size))
	} else {
		res.Header.Set("Content-Length", fmt.Sprint(stat.Size))
	}
	if netreq.DoLog {
		log.Printf("Run %s %v", rcloneBinary, args)
	}
	body, err := runProcess(req.Context(), rcloneBinary, args, netreq.Timeout, netreq.Debug)
	return processResponse(body, err, ""), nil
}

func FetchUrl(netreq *NetRequest) (*http.Response, error) {
	if strings.HasPrefix(netreq.Req.URL.Scheme, "curl+") && len(netreq.Req.URL.Scheme) > 5 {
		netreq.Req.URL.Scheme = netreq.Req.URL.Scheme[5:]
		return fetchCurl(netreq)
	}
	if netreq.Req.URL.Scheme != "http" && netreq.Req.URL.Scheme != "https" &&
		netreq.Req.Method != http.MethodGet && netreq.Req.Method != http.MethodHead &&
		netreq.Req.Method != http.MethodOptions {
		return &http.Response{
			StatusCode: http.StatusMethodNotAllowed,
			Header: http.Header{
				"Allow": []string{"OPTIONS, GET, HEAD"},
			},
		}, nil
	}
	switch netreq.Req.URL.Scheme {
	case "unix":
		return fetchUnix(netreq.Req)
	case "file":
		return fetchFile(netreq.Req)
	case "rclone":
		return fetchRclone(netreq)
	case "exec":
		return fetchExec(netreq)
	default:
		return fetchHttp(netreq)
	}
}

// Parse standard HTTP_PROXY, HTTPS_PROXY, NO_PROXY (and lowercase versions) envs, return proxy for urlStr.
func ParseProxyFromEnv(urlStr string) string {
	if urlStr == "" {
		return ""
	}
	urlObj, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	proxyUrl, err := http.ProxyFromEnvironment(&http.Request{URL: urlObj})
	if err != nil || proxyUrl == nil {
		return ""
	}
	return proxyUrl.String()
}

func getUrlPatternParts(pattern string) map[string]string {
	if pattern == "<all_urls>" {
		return map[string]string{
			"scheme": "*",
			"host":   "*",
			"path":   "*",
		}
	}
	matchScheme := `(\*|[a-z][\+a-z0-9]*)`
	matchHost := `(\*|(?:\*\.)?(?:[^/*]+))?`
	matchPath := `(/.*)?`
	regex := regexp.MustCompile("^" + matchScheme + "://" + matchHost + matchPath + "$")
	result := regex.FindStringSubmatch(pattern)
	if result == nil {
		return nil
	}
	return map[string]string{
		"scheme": result[1],
		"host":   result[2],
		"path":   result[3],
	}
}

// Create a Chrome extension match pattern style matcher, that test a url against the pattern.
// Mattern syntax: https://developer.chrome.com/docs/extensions/develop/concepts/match-patterns .
// Pattern examples: https://*/ , https://*/foo* , https://*.google.com/foo*bar .
// Adapted from https://github.com/nickclaw/url-match-patterns
func CreateUrlPatternMatcher(pattern string) func(string) bool {
	parts := getUrlPatternParts(pattern)
	if parts == nil {
		return func(_ string) bool { return false }
	}
	str := "^"
	if parts["scheme"] == "*" {
		str += "(http|https)"
	} else {
		str += parts["scheme"]
	}
	str += "://"
	if parts["host"] == "*" {
		str += ".*"
	} else if len(parts["host"]) >= 2 && parts["host"][:2] == "*." {
		str += `.*`
		str += `\.`
		str += regexp.QuoteMeta(parts["host"][2:])
	} else if parts["host"] != "" {
		str += parts["host"]
	}
	if parts["path"] == "" || parts["path"] == "/" {
		str += "/?"
	} else if parts["path"] == "/*" { // "/*" matches with any path
		str += "(/.*)?"
	} else {
		str += regexp.MustCompile(`\\\*`).ReplaceAllString(regexp.QuoteMeta(parts["path"]), ".*")
	}
	str += "$"
	// fmt.Printf("actual pattern: %s\n", str)
	regex := regexp.MustCompile(str)
	return func(url string) bool {
		return regex.MatchString(url)
	}
}

func MatchUrlPattern(pattern string, optionalUrl string) bool {
	matcher := CreateUrlPatternMatcher(pattern)
	return matcher(optionalUrl)
}

func MatchUrlPatterns(patterns []string, url string, matchempty bool) bool {
	if url == "" {
		if matchempty && slices.Index(patterns, "") != -1 {
			return true
		}
	} else {
		for _, pattern := range patterns {
			if pattern != "" && MatchUrlPattern(pattern, url) {
				return true
			}
		}
	}
	return false
}

var commaSeperatorRegexp = regexp.MustCompile(`,\s*`)

// split a csv like line to values. "a, b, c" => [a,b,c].
// If str is empty string, return nil.
func SplitCsv(str string) []string {
	if str == "" {
		return nil
	}
	return commaSeperatorRegexp.Split(str, -1)
}

func ParseLocalDateTime(str string) (int64, error) {
	if t, error := time.Parse("2006-01-02T15:04:05Z", str); error == nil {
		return t.Unix(), nil
	}
	formats := []string{
		"2006-01-02",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05-07:00",
	}
	for _, format := range formats {
		if t, error := time.ParseInLocation(format, str, time.Local); error == nil {
			return t.Unix(), nil
		}
	}
	return 0, fmt.Errorf("invalid date str")
}

func PrintJson(output io.Writer, value any) error {
	bytes, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal json: %w", err)
	}
	fmt.Fprintln(output, string(bytes))
	return nil
}

// Return t unconditionally.
func First[T any](t T, args ...any) T {
	return t
}

func FileContentType(path string) string {
	contentType := mime.TypeByExtension(filepath.Ext(path))
	if contentType == "" {
		contentType = constants.DEFAULT_MIME
	}
	return contentType
}

// Get "Conten-Type" value from str. str could be:
// already a mediatype or content-type (do nothing);
// or a file ext (with or without leading dot) or file name.
func ContentType(str string) string {
	if !strings.Contains(str, `/`) {
		if !strings.Contains(str, ".") {
			str = "." + str
		}
		return FileContentType(str)
	} else {
		return str
	}
}

type prefixReadCloser struct {
	io.Reader
	rc io.ReadCloser
}

func (p *prefixReadCloser) Close() error {
	return p.rc.Close()
}

// Return io.ReadCloser that return prefix, then read from rc.
func ReadCloserWithAddition(rc io.ReadCloser, prefix, suffix io.Reader) io.ReadCloser {
	var readers []io.Reader
	if prefix != nil {
		readers = append(readers, prefix)
	}
	readers = append(readers, rc)
	if suffix != nil {
		readers = append(readers, suffix)
	}
	return &prefixReadCloser{
		Reader: io.MultiReader(readers...),
		rc:     rc,
	}
}

// onetimeBuffer is a io.Reader, that can only be written once using WriteOnce.
// When Read() is called, if WriteOnce is still not called, it blocks;
// after WriteOnce is called, it return the written data and then EOF to reader.
type onetimeBuffer struct {
	buf  bytes.Buffer
	done chan struct{}
}

func NewOnetimeBuffer() *onetimeBuffer {
	return &onetimeBuffer{
		done: make(chan struct{}),
	}
}

func (ob *onetimeBuffer) Read(p []byte) (n int, err error) {
	<-ob.done
	return ob.buf.Read(p)
}

func (ob *onetimeBuffer) WriteOnce(p []byte) (n int, err error) {
	select {
	case _, ok := <-ob.done:
		if !ok {
			return 0, fmt.Errorf("channel is closed")
		}
	default:
	}
	close(ob.done)
	return ob.buf.Write(p)
}

// Tell if abspath is a file system root path (e.g. "/" or "C:\")
// abspath should be a Cleaned absolute file path.
func IsRootPath(abspath string) bool {
	return abspath == "" || abspath == "." || strings.HasSuffix(abspath, "/") || strings.HasSuffix(abspath, `\`) ||
		regexp.MustCompile(`^[a-zA-Z]:$`).MatchString(abspath)
}

// parse a "file://" (or custom scheme with same struct) url, extract full file system path.
// If url is malformed or invalid, it just returns empty string.
// E.g. "file:///root/a.txt" => "/root/a.txt".
// If windows is true, it will treat url as a windows path:
// 1. Use "\" as path sep instead of `/`. 2. support unc pathes:
// "file://server/folder/data.xml" or "file:////server/folder/data.xml" => "\\server\folder\data.xml".
// 2. support Drive letter in url: "file:///D:/foo.txt" => "D:\foo.txt"
// If windows is false, it will treat a non-empty host in urlObj (except "localhost") as invalid.
// The returned path is NOT cleaned.
// Reference: https://en.wikipedia.org/wiki/File_URI_scheme .
func ParseFileUrlFilepath(urlObj *url.URL, windows bool) string {
	abspath := ""
	if urlObj.Host != "" {
		if windows {
			abspath = `\\` + urlObj.Host
		} else if urlObj.Host != "localhost" {
			return ""
		}
	}
	pathname := urlObj.Path
	if windows {
		if strings.HasPrefix(urlObj.Path, `//`) && abspath != "" {
			return "" // malformed url like "file://server//server", duplicate unc hostname.
		}
		if abspath == "" && regexp.MustCompile(`^/[a-zA-Z]:\/`).MatchString(pathname) {
			pathname = pathname[1:]
		}
	}
	abspath += pathname
	if windows {
		abspath = strings.ReplaceAll(abspath, `/`, `\`)
	}
	return abspath
}

// Similar to ParseFileUrlFilepath, but treat urlObj as a local file system url automatically.
// Also, the returned path is fullpath.Cleaned.
func ParseLocalFileUrlFilepath(urlObj *url.URL) string {
	abspath := ParseFileUrlFilepath(urlObj, runtime.GOOS == "windows")
	if abspath != "" {
		abspath = filepath.Clean(abspath)
	}
	return abspath
}

// Parse binary file path from "exec://" url.
// It's a custom scheme that's different with "file://" scheme that:
// In url parts: if host exists but pathname does not, treat it as a binary in PATH:
// "exec://pwd" => "pwd".
func ParseExecUrlFilepath(urlObj *url.URL) string {
	if urlObj.Host != "" && (urlObj.Path == "" || urlObj.Path == "/") {
		return urlObj.Host
	}
	return ParseLocalFileUrlFilepath(urlObj)
}

// Get from "args" or "arg" variable(s) of query param.
func getArgs(queryParams url.Values) (args []string, err error) {
	if queryParams.Has("args") {
		if args, err = shlex.Split(queryParams.Get("args")); err != nil {
			return nil, fmt.Errorf("invalid arags: %w", err)
		}
	} else {
		args = queryParams["arg"]
	}
	return args, nil
}

func ErrResponseMsg(format string, args ...any) *http.Response {
	return &http.Response{
		StatusCode: http.StatusInternalServerError,
		Header: http.Header{
			"Content-Type": []string{constants.MIME_TXT},
		},
		Body: io.NopCloser(strings.NewReader(fmt.Sprintf(format, args...))),
	}
}

// Return a http 416 range not satisfiable response.
func errResponseInvalidRange(size int64) *http.Response {
	return &http.Response{
		StatusCode: http.StatusRequestedRangeNotSatisfiable,
		Header: http.Header{
			"Content-Range": []string{fmt.Sprintf("bytes */%d", size)},
		},
	}
}

// Return a http response for err.
func processResponse(body io.ReadCloser, err error, okMime string) *http.Response {
	var status int
	if err == nil {
		status = http.StatusOK
	} else {
		status = http.StatusInternalServerError
	}
	var mime string
	if err == nil && okMime != "" {
		mime = okMime
	} else {
		mime = constants.MIME_TXT
	}
	if body == nil && err != nil {
		body = io.NopCloser(strings.NewReader(fmt.Sprintf("process error: %v", err)))
	}
	return &http.Response{
		StatusCode: status,
		Header: http.Header{
			"Content-Type": []string{mime},
		},
		Body: body,
	}
}

// Encrypt data using cipher, return []byte
func Encrypt(cipher cipher.AEAD, plaindata []byte) (cipherstring []byte) {
	nonce := make([]byte, cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	cipherdata := cipher.Seal(nonce, nonce, plaindata, nil)
	return cipherdata
}

// Encrypt data using cipher, return base62 string of nonce+cipherdata
func EncryptToString(cipher cipher.AEAD, plaindata []byte) (cipherstring string) {
	return base62.EncodeToString(Encrypt(cipher, plaindata))
}

// Encrypt data using cipher, return base64 string of nonce+cipherdata
func EncryptToBase64String(cipher cipher.AEAD, plaindata []byte) (cipherstring string) {
	return base64.StdEncoding.EncodeToString(Encrypt(cipher, plaindata))
}

func Decrypt(cipher cipher.AEAD, cipherdata []byte) (plaindata []byte, err error) {
	if len(cipherdata) <= cipher.NonceSize() {
		return nil, fmt.Errorf("ciperdata too small")
	}
	return cipher.Open(nil, cipherdata[:cipher.NonceSize()], cipherdata[cipher.NonceSize():], nil)
}

// ciphertext should be the result of EncryptToBase64String
func DecryptBase64String(cipher cipher.AEAD, ciphertext string) (plaindata []byte, err error) {
	cipherdata, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	return Decrypt(cipher, cipherdata)
}

// ciphertext (base62 string) should be the result of EncryptToString
func DecryptString(cipher cipher.AEAD, ciphertext string) (plaindata []byte, err error) {
	cipherdata, err := base62.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	return Decrypt(cipher, cipherdata)
}

// Return a AES-256-GCM cipher using key derived from either or both of passphrase and ECDH key exchange.
// privatekey & remotePublickey should be generated by Curve25519.
// To generate privatekey: ecdh.X25519().GenerateKey(rand.Reader).
func GetPublickeyCipher(passphrase string, salt string, iter int,
	privatekey *ecdh.PrivateKey, remotePublickey *ecdh.PublicKey) (
	c cipher.AEAD, err error) {
	if passphrase == "" && privatekey == nil {
		return nil, fmt.Errorf("at least one of passphrase and privatekey must be set")
	}
	var key []byte
	if passphrase != "" {
		key = pbkdf2.Key([]byte(passphrase), []byte(salt), iter, 32, sha256.New)
	}
	if privatekey != nil {
		// Curve25519 ECDH generate 32 bytes secret
		secret, err := privatekey.ECDH(remotePublickey)
		if err != nil {
			return nil, fmt.Errorf("failed to derive ecdh shared secret: %w", err)
		}
		secretKey := pbkdf2.Key(secret, nil, 1, 32, sha256.New)
		if key != nil {
			for i := range key {
				key[i] ^= secretKey[i]
			}
		} else {
			key = secretKey
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c, err = cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Get a cipher from passphrase and salt
func GetCipher(passphrase string, salt string, iter int) (cipher.AEAD, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("passphrase can not be empty")
	}
	key := pbkdf2.Key([]byte(passphrase), []byte(salt), iter, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Parse http content-type header and return mediatype, e.g. "text/html".
// contentType: the http Content-Type header, e.g. "text/html; charset=utf-8"
func MediaType(contentType string) string {
	if contentType != "" {
		if mediatype, _, err := mime.ParseMediaType(contentType); err == nil {
			return mediatype
		}
	}
	return ""
}

func IsTextualMediaType(mediatype string) bool {
	return mediatype != "" && (strings.HasPrefix(mediatype, "text/") || constants.TextualMediatypes[mediatype])
}

// Unmarshal a json / yaml / toml / xml string according to contentType.
// contentType could be: a mediatype (e.g. "application/json"), or a file type (e.g. "json").
// If contentType is empty or is not a supported type, return nil, nil.
func Unmarshal(contentType string, input io.Reader) (data any, err error) {
	body, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("failed to read input: %w", err)
	}
	if strings.ContainsRune(contentType, '/') {
		contentType = MediaType(contentType)
	}
	if len(body) > 0 {
		switch contentType {
		case "application/json", "text/json", "json":
			err = json.Unmarshal(body, &data)
		case "application/yaml", "text/yaml", "yaml":
			err = yaml.Unmarshal(body, &data)
		case "application/xml", "text/xml", "xml":
			err = xml.Unmarshal(body, &data)
		case "application/toml", "text/toml", "toml":
			err = toml.Unmarshal(body, &data)
		}
	}
	return data, err
}

func Marshal(contentType string, input any) (data []byte, err error) {
	if strings.ContainsRune(contentType, '/') {
		contentType = MediaType(contentType)
	}
	switch contentType {
	case "application/json", "text/json", "json":
		data, err = json.Marshal(input)
	case "application/yaml", "text/yaml", "yaml":
		data, err = yaml.Marshal(input)
	case "application/xml", "text/xml", "xml":
		data, err = xml.Marshal(input)
	case "application/toml", "text/toml", "toml":
		data, err = toml.Marshal(input)
	}
	return data, err
}

// Return a cryptographically secure random string of format /[a-zA-Z0-9]{length}/
func RandString(length int) string {
	if length <= 0 {
		return ""
	}
	const rand_chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var sb strings.Builder
	var max byte = byte(math.Floor(float64(math.MaxUint8/len(rand_chars))) * float64(len(rand_chars)))
	buf := make([]byte, length)
outer:
	for {
		if _, err := rand.Read(buf); err != nil {
			panic("rand.Read() failed")
		}
		for _, byte := range buf {
			// By taking only the numbers up to a multiple of char space size and discarding others,
			// we expect a uniform distribution of all possible chars.
			if byte < max {
				sb.WriteByte(rand_chars[int(byte)%len(rand_chars)])
			}
			if sb.Len() >= length {
				break outer
			}
		}
	}
	return sb.String()
}
