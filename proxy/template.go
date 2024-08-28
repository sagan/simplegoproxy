package proxy

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/sagan/simplegoproxy/util"
	"gopkg.in/yaml.v3"
)

// template functions
var templateFuncMap = map[string]any{
	"btoa":         btoa,
	"atob":         atob,
	"upper":        upper,
	"lower":        lower,
	"atoi":         atoi,
	"join":         join,
	"split":        split,
	"trim":         trim,
	"replace":      replaceFunc,
	"replace_once": replace_once,
	"trimprefix":   trimprefix,
	"trimsuffix":   trimsuffix,
	"json_encode":  json_encode,
	"json_decode":  json_decode,
	"yaml_encode":  yaml_encode,
	"yaml_decode":  yaml_decode,
}

// privileged template functions, require url be signed.
var templateAdminFuncMap = map[string]any{
	"fetch": fetch,
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

// string to upper
func upper(input any) string {
	return strings.ToUpper(any2string(input))
}

// string to lower
func lower(input any) string {
	return strings.ToLower(any2string(input))
}

// Convert input to int. if failed to parse input as int, return 0.
func atoi(input any) int {
	i, err := strconv.Atoi(any2string(input))
	if err != nil {
		return 0
	}
	return i
}

// string to upper
func join(input []any, deli any) string {
	str := ""
	deliStr := any2string(deli)
	for i, el := range input {
		if i > 0 {
			str += deliStr
		}
		str += any2string(el)
	}
	return str
}

// Split input to slice separated by deli.
// If input is empty string, return nil.
func split(input any, deli any) []string {
	str := any2string(input)
	if str == "" {
		return nil
	}
	return strings.Split(str, any2string(deli))
}

func trim(input any) string {
	return strings.TrimSpace(any2string(input))
}

func trimprefix(input any, prefix any) string {
	return strings.TrimPrefix(any2string(input), any2string(prefix))
}

func trimsuffix(input any, suffix any) string {
	return strings.TrimSuffix(any2string(input), any2string(suffix))
}

func json_encode(input any) string {
	output, err := json.Marshal(input)
	if err != nil {
		return ""
	}
	return string(output)
}

func json_decode(input any) any {
	var output any
	err := json.Unmarshal([]byte(any2string(input)), &output)
	if err != nil {
		return nil
	}
	return &output
}

func yaml_encode(input any) string {
	output, err := yaml.Marshal(input)
	if err != nil {
		return ""
	}
	return string(output)
}

func yaml_decode(input any) any {
	var output any
	err := yaml.Unmarshal([]byte(any2string(input)), &output)
	if err != nil {
		return nil
	}
	return &output
}

func replaceFunc(input, old, new any) string {
	return strings.ReplaceAll(any2string(input), any2string(old), any2string(new))
}

func replace_once(input, old, new any) string {
	return strings.Replace(any2string(input), any2string(old), any2string(new), 1)
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
	Err    error
	Status int
	Header http.Header
	Body   string
	Data   any
}

func fetch(urlStr string, options ...string) *Response {
	response := &Response{}
	req, err := http.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		response.Err = err
		return response
	}
	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions,
		http.MethodHead}
	for _, option := range options {
		switch {
		case slices.Contains(methods, option):
			req.Method = option
		case strings.HasPrefix(option, "@"):
			req.Body = io.NopCloser(strings.NewReader(option[1:]))
		case strings.ContainsRune(option, ':'):
			key, value, _ := strings.Cut(option, ":")
			req.Header.Add(strings.TrimSpace(key), strings.TrimSpace(value))
		}
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		response.Err = err
		return response
	}
	response.Header = res.Header
	response.Status = res.StatusCode
	body, err := io.ReadAll(res.Body)
	if err != nil {
		response.Err = err
		return response
	}
	response.Body = string(body)
	var data any
	switch util.ParseMediaType(res.Header.Get("Content-Type")) {
	case "application/json", "text/json", "json":
		err = json.Unmarshal(body, &data)
	case "application/yaml", "text/yaml", "yaml":
		err = yaml.Unmarshal(body, &data)
	case "application/xml", "text/xml", "xml":
		err = xml.Unmarshal(body, &data)
	case "application/toml", "text/toml", "toml":
		err = toml.Unmarshal(body, &data)
	}
	response.Data = data
	response.Err = err
	return response
}
