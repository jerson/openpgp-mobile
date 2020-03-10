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

android: deps
	mkdir -p output/android
	gomobile bind -ldflags="-w -s" -target=android -o output/android/openpgp.aar github.com/jerson/openpgp-mobile/openpgp

ios: deps
	mkdir -p output/ios
	gomobile bind -ldflags="-w -s" -target=ios -o output/ios/Openpgp.framework github.com/jerson/openpgp-mobile/openpgp

swig:
	swig -go -cgo -c++ -intgosize 64 binding/openpgp_bridge/openpgp_bridge.i

binding_all: binding_darwin binding_windows binding_linux

binding_darwin: binding_darwin_386 binding_darwin_amd64

binding_darwin_386:
	GOOS=darwin GOARCH=386 BINDING_FILE=openpgp.dylib TAG=darwin ./cross_build.sh

binding_darwin_amd64:
	GOOS=darwin GOARCH=amd64 BINDING_FILE=openpgp.dylib TAG=darwin ./cross_build.sh

binding_linux: binding_linux_386 binding_linux_amd64 binding_linux_arm64 binding_linux_arm7

binding_linux_386:
	GOOS=linux GOARCH=386 BINDING_FILE=openpgp.so TAG=main ./cross_build.sh

binding_linux_amd64:
	GOOS=linux GOARCH=amd64 BINDING_FILE=openpgp.so TAG=main ./cross_build.sh

binding_linux_arm64:
	GOOS=linux GOARCH=arm64 BINDING_FILE=openpgp.so TAG=arm ./cross_build.sh

binding_linux_arm7:
	GOOS=linux GOARCH=arm7 BINDING_FILE=openpgp.so TAG=arm ./cross_build.sh

binding_windows: binding_windows_386 binding_windows_amd64

binding_windows_386:
	GOOS=windows GOARCH=386 BINDING_FILE=openpgp.dll TAG=main ./cross_build.sh

binding_windows_amd64:
	GOOS=windows GOARCH=amd64 BINDING_FILE=openpgp.dll TAG=main ./cross_build.sh

binding: deps
	mkdir -p output/binding
	go build -ldflags="-w" -o output/binding/$(BINDING_FILE) -buildmode=c-shared binding/main.go