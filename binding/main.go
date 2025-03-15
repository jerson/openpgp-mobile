package main

//#include <stdint.h>
//#include <stdlib.h>
//typedef struct  { void* message; int size; char* error; } BytesReturn;
import "C"
import (
	"unsafe"

	"github.com/jerson/helpers-mobile/codecs"

	openPGPBridge "github.com/jerson/openpgp-mobile/bridge"
)

//export OpenPGPBridgeCall
func OpenPGPBridgeCall(name *C.char, payload unsafe.Pointer, payloadSize C.int) *C.BytesReturn {
	result, err := openPGPBridge.Call(C.GoString(name), C.GoBytes(payload, payloadSize))
	return createBytesReturn(result, err)
}

//export OpenPGPEncodeText
func OpenPGPEncodeText(input *C.char, encoding *C.char) *C.BytesReturn {
	result, err := codecs.TextEncode(C.GoString(input), C.GoString(encoding))
	return createBytesReturn(result, err)
}

//export OpenPGPDecodeText
func OpenPGPDecodeText(input unsafe.Pointer, size C.int, encoding *C.char, fatal C.int, ignoreBOM C.int, stream C.int) *C.char {
	inputBytes := C.GoBytes(input, size)
	options := codecs.TextDecoderOptions{Fatal: fatal != 0, IgnoreBOM: ignoreBOM != 0}
	decodeOptions := codecs.TextDecodeOptions{Stream: stream != 0}
	result, err := codecs.TextDecode(inputBytes, C.GoString(encoding), options, decodeOptions)
	if err != nil {
		return C.CString("")
	}
	return C.CString(result)
}

func createBytesReturn(result []byte, err error) *C.BytesReturn {
	output := (*C.BytesReturn)(C.malloc(C.size_t(unsafe.Sizeof(C.BytesReturn{}))))
	// we should free resources on dart side

	if err != nil {
		output.error = C.CString(err.Error())
		return output
	}
	output.error = nil
	output.message = C.CBytes(result)
	output.size = C.int(len(result))
	return output
}

func main() {}
