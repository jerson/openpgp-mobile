BINDING_FILE?=openpgp.so
PROTO_DIR = ${GOPATH}/src/github.com/gogo/protobuf/protobuf
DEPLOYER_DIR = ../deployer/pkg/connector

.PHONY: proto

default: fmt test

deps:
	go mod download
	go get -u github.com/gogo/protobuf/protoc-gen-gofast
	go get -u github.com/gogo/protobuf/protoc-gen-gogofast
	go get -u github.com/gogo/protobuf/protoc-gen-gogofaster
	go get -u github.com/gogo/protobuf/protoc-gen-gogoslick

proto: clean
	protoc -Iproto --gofast_out=grpc:./bridge/model proto/*.proto

test:
	go test ./... -coverprofile=profile.cov -cover -short -count 1

fmt:
	go fmt ./...

clean:
	rm -rf output
	rm -rf bridge/model && mkdir -p bridge/model

all: clean binding android ios wasm

gomobile:
	GO111MODULE=off go get golang.org/x/mobile/cmd/gomobile
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

binding_all: binding_windows binding_linux binding_darwin

binding_linux: binding_linux_386 binding_linux_amd64 binding_linux_arm64 binding_linux_armv7

binding_linux_386:
	GOOS=linux GOARCH=386 TAG=main \
	ARGS="-e BINDING_FILE=openpgp_linux_386.so" \
	CMD="make binding" ./cross_build.sh

binding_linux_amd64:
	GOOS=linux GOARCH=amd64 TAG=main \
	ARGS="-e BINDING_FILE=openpgp_linux_amd64.so" \
	CMD="make binding" ./cross_build.sh

binding_linux_arm64:
	GOOS=linux GOARCH=arm64 TAG=arm \
	ARGS="-e BINDING_FILE=openpgp_linux_arm64.so" \
	CMD="make binding" ./cross_build.sh

binding_linux_armv7:
	GOOS=linux GOARCH=armv7 TAG=arm \
	ARGS="-e BINDING_FILE=openpgp_linux_armv7.so" \
	CMD="make binding" ./cross_build.sh

binding_windows: binding_windows_386 binding_windows_amd64

binding_windows_386:
	GOOS=windows GOARCH=386 \
	ARGS="-e BINDING_FILE=openpgp_windows_386.dll" \
	TAG=main CMD="make binding" ./cross_build.sh

binding_windows_amd64:
	GOOS=windows GOARCH=amd64 TAG=main \
	ARGS="-e BINDING_FILE=openpgp_windows_amd64.dll" \
	CMD="make binding" ./cross_build.sh

binding_darwin: binding_darwin_amd64

binding_darwin_amd64:
	GOOS=darwin GOARCH=amd64 TAG=darwin \
	ARGS="-e BINDING_FILE=openpgp_darwin_amd64.dylib" \
	CMD="make binding" ./cross_build.sh

binding_ios: binding_ios_arm64

binding_ios_arm64:
	GOOS=darwin GOARCH=arm64 TAG=darwin \
	ARGS="-e BINDING_FILE=openpgp_ios_arm64.dylib" \
	CMD="make binding" ./cross_build.sh

binding: deps
	mkdir -p output/binding
	go build -ldflags="-w" -o output/binding/$(BINDING_FILE) -buildmode=c-shared binding/main.go