module github.com/jerson/openpgp-mobile

go 1.13

require (
	github.com/ProtonMail/go-crypto v0.0.0-20230321124908-8712db92986c
	github.com/google/flatbuffers v2.0.6+incompatible
	golang.org/x/crypto v0.12.0
)

replace github.com/ProtonMail/go-crypto => github.com/ProtonMail/go-crypto v0.0.0-20230321124908-8712db92986c

replace golang.org/x/crypto => golang.org/x/crypto v0.12.0
