
gomobile:
	gomobile bind -target=android -o openpgp.aar github.com/jerson/openpgp-mobile/mobile


gomobile-ios:
	gomobile bind -target=ios -o openpgp.framework github.com/jerson/openpgp-mobile/mobile
