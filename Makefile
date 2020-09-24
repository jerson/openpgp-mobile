BINDING_NAME?=libopenpgp_bridge
BINDING_FILE?=$(BINDING_NAME).so
BINDING_ARGS?=
BUILD_MODE?=c-shared
OUTPUT_DIR?=output

include Makefile.android
include Makefile.ios
include Makefile.darwin
include Makefile.linux
include Makefile.windows
include Makefile.gomobile
include Makefile.wasm
include Makefile.protobuf

default: fmt test

deps:
	go mod download

test:
	go test ./openpgp/... -coverprofile=profile.cov -cover -short -count 1

fmt:
	go fmt ./...

clean:
	rm -rf output

all: clean binding android ios wasm

binding_all: binding_windows binding_linux binding_darwin

binding: deps
	mkdir -p $(OUTPUT_DIR)/binding
	go build -ldflags="-w -s" -o $(OUTPUT_DIR)/binding/$(BINDING_FILE) -buildmode=$(BUILD_MODE) $(BINDING_ARGS) binding/main.go
