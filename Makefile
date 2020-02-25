

default: fmt test

deps: 
	go mod download

test:
	go test ./...

fmt:
	go fmt ./...

all: android ios

gomobile:
	go get golang.org/x/mobile/cmd/gomobile
	gomobile init

android: deps
	mkdir -p output/android
	gomobile bind -ldflags="-w -s" -target=android -o output/android/openpgp.aar github.com/jerson/openpgp-mobile/openpgp

ios: deps
	mkdir -p output/ios
	gomobile bind -ldflags="-w -s" -target=ios -o output/ios/Openpgp.framework github.com/jerson/openpgp-mobile/openpgp
