package openPGPBridge

import (
	"testing"
)

func TestCall(t *testing.T) {
	data, err := Call("generate", nil)
	if err != nil {
		t.Fatal(err)
		return
	}
	t.Log(data)
}
