default: fmt test

deps: 
	go mod download

test:
	go test ./...

fmt:
	go fmt ./...

clean:
	rm -rf output

all: clean binding archive android ios wasm

gomobile:
	go get golang.org/x/mobile/cmd/gomobile
	gomobile init

.PHONY: wasm
wasm:
	mkdir -p output/wasm
	GOARCH=wasm GOOS=js go build -ldflags="-s -w" -o output/wasm/openpgp.wasm wasm/main.go
	cp output/wasm/openpgp.wasm wasm/sample/public/openpgp.wasm

swig:
	swig -go -cgo -c++ -intgosize 64 binding/openpgp_bridge/openpgp_bridge.i

binding: deps
	mkdir -p output/binding
	go build -ldflags="-w" -o output/binding/openpgp.so -buildmode=c-shared binding/main.go

archive: deps
	mkdir -p output/archive
	go build -ldflags="-w" -o output/archive/openpgp.a -buildmode=c-archive binding/main.go

android: deps
	mkdir -p output/android
	gomobile bind -ldflags="-w -s" -target=android -o output/android/openpgp.aar github.com/jerson/openpgp-mobile/openpgp

ios: deps
	mkdir -p output/ios
	gomobile bind -ldflags="-w -s" -target=ios -o output/ios/Openpgp.framework github.com/jerson/openpgp-mobile/openpgp
