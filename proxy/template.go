package proxy

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// template functions
var templateFuncMap map[string]any

// Base64 decode
func btoa(input any) string {
	var data string
	switch value := input.(type) {
	case string:
		data = value
	case []byte:
		data = string(value)
	default:
		return ""
	}
	output, _ := base64.StdEncoding.DecodeString(data)
	return string(output)
}

// Base64 encode
func atob(input any) string {
	var data []byte
	switch value := input.(type) {
	case string:
		data = []byte(value)
	case []byte:
		data = value
	default:
		data = []byte(fmt.Sprint(value))
	}
	return base64.StdEncoding.EncodeToString(data)
}

// string to upper
func upper(input any) string {
	return strings.ToUpper(fmt.Sprint(input))
}

// string to lower
func lower(input any) string {
	return strings.ToLower(fmt.Sprint(input))
}

// parse int
func atoi(input any) int {
	i, err := strconv.Atoi(fmt.Sprint(input))
	if err != nil {
		return 0
	}
	return i
}

// string to upper
func join(input []any, deli any) string {
	str := ""
	deliStr := fmt.Sprint(deli)
	for i, el := range input {
		if i > 0 {
			str += deliStr
		}
		str += fmt.Sprint(el)
	}
	return str
}

func split(input any, deli any) []string {
	str := fmt.Sprint(input)
	if str == "" {
		return nil
	}
	return strings.Split(str, fmt.Sprint(deli))
}

func trim(input any) string {
	return strings.TrimSpace(fmt.Sprint(input))
}
func trimprefix(input any, prefix any) string {
	return strings.TrimPrefix(fmt.Sprint(input), fmt.Sprint(prefix))
}

func trimsuffix(input any, suffix any) string {
	return strings.TrimSuffix(fmt.Sprint(input), fmt.Sprint(suffix))
}

func init() {
	templateFuncMap = map[string]any{
		"btoa":       btoa,
		"atob":       atob,
		"upper":      upper,
		"lower":      lower,
		"atoi":       atoi,
		"join":       join,
		"split":      split,
		"trim":       trim,
		"trimprefix": trimprefix,
		"trimsuffix": trimsuffix,
	}
}
