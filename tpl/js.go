package tpl

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/dop251/goja"

	"github.com/sagan/simplegoproxy/constants"
)

type JsTpl struct {
	Vm       *goja.Runtime
	Template string
}

func (jp *JsTpl) Execute(wr io.Writer, data any) error {
	v, e := Eval(jp.Vm, jp.Template)
	if e != nil {
		return e
	}
	if _, err := wr.Write(any2byteslice(v)); err != nil {
		return err
	}
	return nil
}

var _ constants.Template = (*JsTpl)(nil)

// Template functions are also available in JavaScript runtime.
// Some funcs are added to it in init().
// Additionally, set_status & set_body & set_header & clear_header funcs are also available in JavaScript runtime.
var JsFuncs = map[string]any{
	"btoa": btoa,
	"atob": atob,
	"env":  os.Getenv,
}

func init() {
	jsfuncs := []string{"fetch", "exec", "system", "randstring", "encrypt", "decrypt",
		"encrypt_binary", "decrypt_binary", "marshal", "unmarshal", "shlex_split"}
	for _, name := range jsfuncs {
		function := TemplateFuncMap[name]
		if function == nil {
			panic(fmt.Sprintf("func %s not found", name))
		}
		JsFuncs[name] = function
	}
}

func Eval(vm *goja.Runtime, input any) (any, error) {
	value, err := vm.RunString(Any2string(input))
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, nil
	}
	v := value.Export()
	if v == nil {
		return nil, nil
	}
	if p, ok := v.(*goja.Promise); ok {
		return ResolveGojaPromise(p)
	}
	return v, nil
}

func ResolveGojaPromise(p *goja.Promise) (any, error) {
	switch p.State() {
	case goja.PromiseStateRejected:
		return nil, fmt.Errorf("promise rejected: %v", p.Result().Export())
	case goja.PromiseStateFulfilled:
		return p.Result().Export(), nil
	default:
		return nil, fmt.Errorf("invalid promise")
	}
}

// Base64 decode
func atob(input any) string {
	output, _ := base64.StdEncoding.DecodeString(Any2string(input))
	return string(output)
}

// Base64 encode
func btoa(input any) string {
	return base64.StdEncoding.EncodeToString([]byte(Any2string(input)))
}
