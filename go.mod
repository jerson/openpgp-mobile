module github.com/jerson/openpgp-mobile

go 1.13

require (
	github.com/gogo/protobuf v1.3.2
	github.com/keybase/go-crypto v0.0.0-20200123153347-de78d2cb44f4
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
	golang.org/x/mobile v0.0.0-20210220033013-bdb1ca9a1e08 // indirect
	golang.org/x/mod v0.4.2 // indirect
)

replace github.com/keybase/go-crypto => github.com/keybase/go-crypto v0.0.0-20200123153347-de78d2cb44f4

replace golang.org/x/crypto => golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897

replace golang.org/x/net => golang.org/x/net v0.0.0-20190620200207-3b0461eec859

replace golang.org/x/sync => golang.org/x/sync v0.0.0-20201020160332-67f06af15bc9

replace golang.org/x/sys => golang.org/x/sys v0.0.0-20190215142949-d0b11bdaac8a

replace golang.org/x/tools => golang.org/x/tools v0.0.0-20200619180055-7c47624df98f

replace golang.org/x/xerrors => golang.org/x/xerrors v0.0.0-20190717185122-a985d3407aa7
