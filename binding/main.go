package main

//#include <stdint.h>
//#include <stdlib.h>
//typedef struct { char *publicKey; char *privateKey; } KeyPair;
//typedef struct { char *hash; char *cipher; char *compression; char *compressionLevel; char *rsaBits; } KeyOptions;
//typedef struct { char *name; char *comment; char *email; char *passphrase; KeyOptions *keyOptions; } Options;
//typedef struct  { KeyPair* keyPair; char* error; } KeyPairReturn;
//typedef struct  { void* message; int size; char* error; } SliceReturn;
//typedef struct  { char* result; char* error; } StringReturn;
//typedef struct  { void* message; int size; char* error; } BytesReturn;
import "C"
import (
	"github.com/jerson/openpgp-mobile/bridge"
	"github.com/jerson/openpgp-mobile/openpgp"
	"strconv"
	"unsafe"
)

//export Call
func Call(name *C.char,payload unsafe.Pointer, payloadSize C.int) *C.BytesReturn {
	output := (*C.BytesReturn)(C.malloc(C.size_t(C.sizeof_BytesReturn)))
	defer C.free(unsafe.Pointer(name))
	defer C.free(payload)

	result, err := bridge.Call(C.GoString(name),C.GoBytes(payload, payloadSize))
	if err != nil {
		output.error = C.CString(err.Error())
		return output
	}
	output.error = nil
	output.message = C.CBytes(result)
	output.size = C.int(len(result))
	return output
}

// in near future we should stop to instance here :D
var instance = openpgp.NewFastOpenPGP()

//export Encrypt
func Encrypt(message, publicKey *C.char) *C.StringReturn {
	output := (*C.StringReturn)(C.malloc(C.size_t(C.sizeof_StringReturn)))
	defer C.free(unsafe.Pointer(publicKey))
	defer C.free(unsafe.Pointer(message))

	result, err := instance.Encrypt(C.GoString(message), C.GoString(publicKey))
	if err != nil {
		output.error = C.CString(err.Error())
		return output
	}
	output.error = nil
	output.result = C.CString(result)
	return output
}

//export EncryptBytes
func EncryptBytes(message unsafe.Pointer, messageSize C.int, publicKey *C.char) *C.SliceReturn {
	output := (*C.SliceReturn)(C.malloc(C.size_t(C.sizeof_SliceReturn)))
	defer C.free(unsafe.Pointer(publicKey))
	defer C.free(message)

	result, err := instance.EncryptBytes(C.GoBytes(message, messageSize), C.GoString(publicKey))
	if err != nil {
		output.error = C.CString(err.Error())
		return output
	}
	output.error = nil
	output.message = C.CBytes(result)
	output.size = C.int(len(result))
	return output
}

//export Decrypt
func Decrypt(message, privateKey, passphrase *C.char) *C.StringReturn {
	output := (*C.StringReturn)(C.malloc(C.size_t(C.sizeof_StringReturn)))
	defer C.free(unsafe.Pointer(passphrase))
	defer C.free(unsafe.Pointer(message))
	defer C.free(unsafe.Pointer(privateKey))

	result, err := instance.Decrypt(C.GoString(message), C.GoString(privateKey), C.GoString(passphrase))
	if err != nil {
		output.error = C.CString(err.Error())
		return output
	}
	output.error = nil
	output.result = C.CString(result)
	return output
}

//export DecryptBytes
func DecryptBytes(message unsafe.Pointer, messageSize C.int, privateKey, passphrase *C.char) *C.SliceReturn {
	output := (*C.SliceReturn)(C.malloc(C.size_t(C.sizeof_SliceReturn)))
	defer C.free(unsafe.Pointer(passphrase))
	defer C.free(unsafe.Pointer(privateKey))
	defer C.free(message)

	result, err := instance.DecryptBytes(C.GoBytes(message, messageSize), C.GoString(privateKey), C.GoString(passphrase))
	if err != nil {
		output.error = C.CString(err.Error())
		return output
	}
	output.error = nil
	output.message = C.CBytes(result)
	output.size = C.int(len(result))
	return output
}

//export Sign
func Sign(message, publicKey, privateKey, passphrase *C.char) *C.StringReturn {
	output := (*C.StringReturn)(C.malloc(C.size_t(C.sizeof_StringReturn)))
	defer C.free(unsafe.Pointer(passphrase))
	defer C.free(unsafe.Pointer(privateKey))
	defer C.free(unsafe.Pointer(publicKey))
	defer C.free(unsafe.Pointer(message))

	result, err := instance.Sign(C.GoString(message), C.GoString(publicKey), C.GoString(privateKey), C.GoString(passphrase))
	if err != nil {
		output.error = C.CString(err.Error())
		return output
	}
	output.error = nil
	output.result = C.CString(result)
	return output
}

//export SignBytes
func SignBytes(message unsafe.Pointer, messageSize C.int, publicKey, privateKey, passphrase *C.char) *C.SliceReturn {
	output := (*C.SliceReturn)(C.malloc(C.size_t(C.sizeof_SliceReturn)))
	defer C.free(unsafe.Pointer(passphrase))
	defer C.free(unsafe.Pointer(privateKey))
	defer C.free(message)

	result, err := instance.SignBytes(C.GoBytes(message, messageSize), C.GoString(publicKey), C.GoString(privateKey), C.GoString(passphrase))
	if err != nil {
		output.error = C.CString(err.Error())
		return output
	}
	output.error = nil
	output.message = C.CBytes(result)
	output.size = C.int(len(result))
	return output
}

//export SignBytesToString
func SignBytesToString(message unsafe.Pointer, messageSize C.int, publicKey, privateKey, passphrase *C.char) *C.StringReturn {
	output := (*C.StringReturn)(C.malloc(C.size_t(C.sizeof_StringReturn)))
	defer C.free(unsafe.Pointer(passphrase))
	defer C.free(unsafe.Pointer(privateKey))
	defer C.free(unsafe.Pointer(publicKey))
	defer C.free(message)

	result, err := instance.SignBytesToString(C.GoBytes(message, messageSize), C.GoString(publicKey), C.GoString(privateKey), C.GoString(passphrase))
	if err != nil {
		output.error = C.CString(err.Error())
		return output
	}
	output.error = nil
	output.result = C.CString(result)
	return output
}

//export Verify
func Verify(signature, message, publicKey *C.char) *C.StringReturn {
	output := (*C.StringReturn)(C.malloc(C.size_t(C.sizeof_StringReturn)))
	defer C.free(unsafe.Pointer(publicKey))
	defer C.free(unsafe.Pointer(message))
	defer C.free(unsafe.Pointer(signature))

	result, err := instance.Verify(C.GoString(signature), C.GoString(message), C.GoString(publicKey))
	if err != nil {
		output.error = C.CString(err.Error())
		return output
	}
	output.error = nil
	if result {
		output.result = C.CString("1")
	} else {
		output.result = C.CString("")
	}
	return output
}

//export VerifyBytes
func VerifyBytes(signature *C.char, message unsafe.Pointer, messageSize C.int, publicKey *C.char) *C.StringReturn {
	output := (*C.StringReturn)(C.malloc(C.size_t(C.sizeof_StringReturn)))
	defer C.free(unsafe.Pointer(publicKey))
	defer C.free(unsafe.Pointer(signature))
	defer C.free(message)

	result, err := instance.VerifyBytes(C.GoString(signature), C.GoBytes(message, messageSize), C.GoString(publicKey))
	if err != nil {
		output.error = C.CString(err.Error())
		return output
	}
	output.error = nil
	if result {
		output.result = C.CString("1")
	} else {
		output.result = C.CString("")
	}
	return output
}

//export EncryptSymmetric
func EncryptSymmetric(message, passphrase *C.char, options *C.KeyOptions) *C.StringReturn {
	output := (*C.StringReturn)(C.malloc(C.size_t(C.sizeof_StringReturn)))
	defer C.free(unsafe.Pointer(options))
	defer C.free(unsafe.Pointer(passphrase))
	defer C.free(unsafe.Pointer(message))

	result, err := instance.EncryptSymmetric(C.GoString(message), C.GoString(passphrase), getKeyOptions(options))
	if err != nil {
		output.error = C.CString(err.Error())
		return output
	}
	output.error = nil
	output.result = C.CString(result)
	return output
}

//export EncryptSymmetricBytes
func EncryptSymmetricBytes(message unsafe.Pointer, messageSize C.int, passphrase *C.char, options *C.KeyOptions) *C.SliceReturn {
	output := (*C.SliceReturn)(C.malloc(C.size_t(C.sizeof_SliceReturn)))
	defer C.free(unsafe.Pointer(options))
	defer C.free(unsafe.Pointer(passphrase))
	defer C.free(message)

	result, err := instance.EncryptSymmetricBytes(C.GoBytes(message, messageSize), C.GoString(passphrase), getKeyOptions(options))
	if err != nil {
		output.error = C.CString(err.Error())
		return output
	}
	output.error = nil
	output.message = C.CBytes(result)
	output.size = C.int(len(result))
	return output
}

//export DecryptSymmetric
func DecryptSymmetric(message, passphrase *C.char, options *C.KeyOptions) *C.StringReturn {
	output := (*C.StringReturn)(C.malloc(C.size_t(C.sizeof_StringReturn)))
	defer C.free(unsafe.Pointer(options))
	defer C.free(unsafe.Pointer(passphrase))
	defer C.free(unsafe.Pointer(message))

	result, err := instance.DecryptSymmetric(C.GoString(message), C.GoString(passphrase), getKeyOptions(options))
	if err != nil {
		output.error = C.CString(err.Error())
		return output
	}
	output.error = nil
	output.result = C.CString(result)
	return output
}

//export DecryptSymmetricBytes
func DecryptSymmetricBytes(message unsafe.Pointer, messageSize C.int, passphrase *C.char, options *C.KeyOptions) *C.SliceReturn {
	output := (*C.SliceReturn)(C.malloc(C.size_t(C.sizeof_SliceReturn)))
	defer C.free(unsafe.Pointer(options))
	defer C.free(unsafe.Pointer(passphrase))
	defer C.free(message)

	result, err := instance.DecryptSymmetricBytes(C.GoBytes(message, messageSize), C.GoString(passphrase), getKeyOptions(options))
	if err != nil {
		output.error = C.CString(err.Error())
		return output
	}
	output.error = nil
	output.message = C.CBytes(result)
	output.size = C.int(len(result))
	return output
}

//export Generate
func Generate(optionsInput *C.Options) *C.KeyPairReturn {
	output := (*C.KeyPairReturn)(C.malloc(C.size_t(C.sizeof_KeyPairReturn)))
	defer C.free(unsafe.Pointer(optionsInput))
	result, err := instance.Generate(getOptions(optionsInput))
	if err != nil {
		output.error = C.CString(err.Error())
		return output
	}
	output.error = nil
	output.keyPair = &C.KeyPair{C.CString(result.PublicKey), C.CString(result.PrivateKey)}
	return output

}

func getKeyOptions(options *C.KeyOptions) *openpgp.KeyOptions {
	if options == nil {
		return &openpgp.KeyOptions{}
	}

	result := &openpgp.KeyOptions{
		Hash:        C.GoString(options.hash),
		Cipher:      C.GoString(options.cipher),
		Compression: C.GoString(options.compression),
	}
	if options.compressionLevel != nil {
		result.CompressionLevel, _ = strconv.Atoi(C.GoString(options.compressionLevel))
	}
	if options.rsaBits != nil {
		result.RSABits, _ = strconv.Atoi(C.GoString(options.rsaBits))
	}
	return result
}

func getOptions(options *C.Options) *openpgp.Options {
	if options == nil {
		return &openpgp.Options{}
	}

	result := &openpgp.Options{
		Name:       C.GoString(options.name),
		Comment:    C.GoString(options.comment),
		Email:      C.GoString(options.email),
		Passphrase: C.GoString(options.passphrase),
	}
	if options.keyOptions != nil {
		result.KeyOptions = getKeyOptions(options.keyOptions)
	}
	return result
}

func main() {}
