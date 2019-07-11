

default: fmt test


test:
	go test ./...

fmt:
	go fmt ./...

android:
	gomobile bind -target=android -o openpgp.aar github.com/jerson/openpgp-mobile/mobile


ios:
	gomobile bind -target=ios -o openpgp.framework github.com/jerson/openpgp-mobile/mobile
