

gomobile:
	gomobile bind -target=android -o openpgp.aar jerson.dev/openpgp/mobile


gomobile-ios:
	gomobile bind -target=ios -o openpgp.framework jerson.dev/openpgp/mobile
