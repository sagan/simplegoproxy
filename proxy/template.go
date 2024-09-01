package proxy

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/sagan/simplegoproxy/util"
)

const NOBODY = "NOBODY"

// Additional template functions, require url to be signed.
// Due to the pipeline way that Go template works, the last argument of funcs shoud be the primary one.
var templateFuncMap = map[string]any{
	"btoa":           btoa,
	"atob":           atob,
	"marshal":        marshal,
	"unmarshal":      unmarshal,
	"randstring":     randstring,
	"encrypt":        encrypt,
	"decrypt":        decrypt,
	"encrypt_binary": encrypt_binary,
	"decrypt_binary": decrypt_binary,
	"neg":            neg,
	"abs":            absFunc,
	"read":           read,
	"fetch":          fetch,
}

// Base64 decode
func atob(input any) string {
	output, _ := base64.StdEncoding.DecodeString(any2string(input))
	return string(output)
}

// Base64 encode
func btoa(input any) string {
	return base64.StdEncoding.EncodeToString([]byte(any2string(input)))
}

// Convert input to int. if failed to parse input as int, return 0.
func atoi(input any) int {
	if input != nil {
		switch v := input.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		}
	}
	i, err := strconv.Atoi(any2string(input))
	if err != nil {
		return 0
	}
	return i
}

func unmarshal(contentType any, input any) any {
	data, _ := util.Unmarshal(any2string(contentType), strings.NewReader(any2string(input)))
	return data
}

func marshal(contentType any, input any) string {
	data, _ := util.Marshal(any2string(contentType), input)
	return string(data)
}

// If input is a string or []byte, return as it.
// Otherwise return nil.
func any2byteslice(input any) []byte {
	if input == nil {
		return nil
	}
	switch value := input.(type) {
	case string:
		return []byte(value)
	case []byte:
		return value
	default:
		return nil
	}
}

// Convert input to string.
// If input is nil, return empty string.
// If input is string or []byte, return as it.
// Otherwise return fmt.Sprint(input).
func any2string(input any) string {
	if input == nil {
		return ""
	}
	switch value := input.(type) {
	case string:
		return value
	case []byte:
		return string(value)
	default:
		return fmt.Sprint(input)
	}
}

type Response struct {
	Err     error
	Status  int
	Header  http.Header
	Body    string
	Data    any
	RawBody io.ReadCloser
}

func fetch(options ...string) *Response {
	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions,
		http.MethodHead}
	urlStr := ""
	nobody := false
	method := http.MethodGet
	header := http.Header{}
	var body io.ReadCloser
	for _, option := range options {
		switch {
		case strings.HasPrefix(option, "http://") || strings.HasPrefix(option, "https://"):
			urlStr = option
		case option == NOBODY:
			nobody = true
		case slices.Contains(methods, option):
			method = option
		case strings.HasPrefix(option, "@"):
			body = io.NopCloser(strings.NewReader(option[1:]))
		case strings.ContainsRune(option, ':'):
			key, value, _ := strings.Cut(option, ":")
			header.Add(strings.TrimSpace(key), strings.TrimSpace(value))
		}
	}

	response := &Response{}
	if urlStr == "" {
		response.Err = fmt.Errorf("no url")
		return response
	}
	req, err := http.NewRequest(method, urlStr, nil)
	if err != nil {
		response.Err = err
		return response
	}
	req.Header = header
	req.Body = body

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		response.Err = err
		return response
	}
	response.Header = res.Header
	response.Status = res.StatusCode
	if !nobody {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			response.Err = err
			return response
		}
		response.Body = string(body)
		data, err := util.Unmarshal(res.Header.Get("Content-Type"), bytes.NewReader(body))
		response.Data = data
		response.Err = err
	} else {
		response.RawBody = res.Body
	}
	return response
}

// Encrypt data to base64 string
func encrypt(password, salt, data any) string {
	return base64.StdEncoding.EncodeToString(encrypt_binary(password, salt, data))
}

// Encrypt data to binary string
func encrypt_binary(password, salt, data any) []byte {
	// if password
	cipher, err := util.GetCipher(any2string(password), any2string(salt))
	if err != nil {
		return nil
	}
	return util.Encrypt(cipher, []byte(any2string(data)))
}

// Decrypt base64 data string
func decrypt(password, salt, data any) string {
	// if password
	cipher, err := util.GetCipher(any2string(password), any2string(salt))
	if err != nil {
		return ""
	}
	plaintext, err := util.DecryptBase64String(cipher, any2string(data))
	if err != nil {
		return ""
	}
	return string(plaintext)
}

// Decrypt binary data
func decrypt_binary(password, salt, data any) string {
	cipher, err := util.GetCipher(any2string(password), any2string(salt))
	if err != nil {
		return ""
	}
	plaintext, err := util.Decrypt(cipher, any2byteslice(data))
	if err != nil {
		return ""
	}
	return string(plaintext)
}

// Get a cryptographically secure random string of "[0-9a-zA-Z]{length}".
func randstring(length any) string {
	return util.RandString(atoi(length))
}

func neg(a any) int {
	return -atoi(a)
}

func absFunc(a any) int {
	v := atoi(a)
	if v < 0 {
		return -v
	}
	return v
}

// Read full contents of a io.Reader or ReadCloser
func read(input any) (data []byte) {
	if input == nil {
		return nil
	}
	switch v := input.(type) {
	case io.ReadCloser:
		data, _ = io.ReadAll(v)
		v.Close()
		return data
	case io.Reader:
		data, _ = io.ReadAll(v)
		return data
	case []byte:
		return v
	case string:
		return []byte(v)
	default:
		return []byte(fmt.Sprint(v))
	}
}
