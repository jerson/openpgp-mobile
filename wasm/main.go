// +build js,wasm

package main

import (
	"errors"
	openPGPBridge "github.com/jerson/openpgp-mobile/bridge"
	"syscall/js"
)

func Promise(i []js.Value, fn func() (result interface{}, err error)) interface{} {
	if len(i) < 1 {
		println(errors.New("error: required at least one argument").Error())
		return nil
	}
	callback := i[len(i)-1:][0]
	if callback.Type() != js.TypeFunction {
		println(errors.New("error: last argument should be a callback(err,result)").Error())
		return nil
	}
	result, err := fn()
	if err != nil {
		callback.Invoke(err.Error(), js.Null())
		return nil
	}
	callback.Invoke(js.Null(), js.ValueOf(result))

	return nil
}

func Call(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		length := i[2].Int()
		received := make([]byte, length)
		js.CopyBytesToGo(received, i[1])
		output, err := openPGPBridge.Call(i[0].String(), received)
		if err != nil {
			return nil, err
		}

		//output:= []byte{}

		dst := js.Global().Get("Uint8Array").New(len(output))
		js.CopyBytesToJS(dst, output)
		return dst, err
	})
}

func registerCallbacks() {
	js.Global().Set("openPGPBridgeCall", js.FuncOf(Call))
}

func main() {
	c := make(chan bool, 0)
	registerCallbacks()
	<-c
}
