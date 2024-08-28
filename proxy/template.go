package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// template functions
var templateFuncMap map[string]any

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

func init() {
	templateFuncMap = map[string]any{
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
}
