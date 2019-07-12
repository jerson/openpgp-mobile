

default: fmt test


test:
	go test ./...

fmt:
	go fmt ./...

android:
	gomobile bind -ldflags="-w -s" -target=android -o openpgp.aar github.com/jerson/openpgp-mobile/mobile


ios:
	gomobile bind -ldflags="-w -s" -target=ios -o openpgp.framework github.com/jerson/openpgp-mobile/mobile
