package tpl

import (
	"github.com/dop251/goja"
)

func Eval(vm *goja.Runtime, input any) any {
	value, err := vm.RunString(Any2string(input))
	if err != nil {
		return nil
	}
	if value == nil {
		return nil
	}
	if p, ok := value.Export().(*goja.Promise); ok {
		switch p.State() {
		case goja.PromiseStateRejected:
			return nil
		case goja.PromiseStateFulfilled:
			return p.Result().Export()
		default:
			return nil
		}
	}
	return value.Export()
}
