package openpgp

import (
	"errors"
	"testing"
)

var message = `-----BEGIN PGP MESSAGE-----
Version: BCPG v1.60

hQEMA8lrFZvFE3EOAQgAwkPZb4dgFnSOV9+nmeQScBZ4dS6Gpn16URZyKcReip16
YwYsCoZWF+rT9WEcpzw+gFV0rjmF8KL6jcxJHO0ZORR6WAtoo3hTGz6Z491zypiP
25tFik8FbDbe9fS64EsnaC2zG+3FE+9YApYUOZt/zWwB3eRgnBVMvV/GszL/DupI
KMnl+/C/YnesWnaKrle11mUi7mMbXMzUFFW8aBNv2/eUolGL6If9AsAErDNC64Ac
Ii+DfRB4pDGK+QbDwXvERmqFYFb1UTHNqG/P1uWFgiY/kxxXWSXM/Jhciln9styu
zJRqrR8J7kzibyTggNEKVr+tENZbHEvl+RUSilLBpNLBywEUDVA3Hu2ZmPAPW+3+
rAj2WBj2KzHTNWCysi8YOyK1j8EZjBT/PA3DKcGciCziCNi0Oe4VtFslDp1VFAl6
4ESYTsR4iXrG8V7021+3ez1kE1fmATfR5ifd4lFnnahhnY0XtAWnhge0ODkF3Z1C
BB1FnjpdBA5XUMN41oSME1RvQTkh1KZBaReHsT2WJy1tKVDKEW5OF4+57WeaDBNq
93uhsdNi3+JMVDFmsHBId8w9kD8AS6vqm+plilltOAJrFjrmP1ayvocbzJUVQjvz
dJ/tC2b5AbkJuZuwVM29kmnR3kSvjxLGE6LzSFL7DW2uIo8BuS3vSBl4S5d6tp8l
yQUL52GARroSefjAf/UO9qhkktX9n6NUOy6F7QoUzL5w4ejBRrqitr7RhZZad6vM
4gTo9UtFPD+zlPYYosheEd+UGjsMxxjCrVnD28oBM+7234j+H9QIG2XyyO2rCzMr
d1fzNMRDACKuHJ9FzuE2basXNxQsZPSM9Mse9R6FKTCBMsQsFVmVm+nnrN33dneK
/6/shV2kyYKLfI/csSS1Vv1i4B8vkJmWBnsuJ6DYJVCZMVzacWlvpj03d556yOnh
eX47UV7aIs6vKAQ+cmuU52JKVcS+pnBAaO2zU9Cz6tjfJfzGt4ZPh/5f2Rcz5mVI
I1jYPn5N0NOvH7nPc27L3pMe8L0S408Znp1MyRV8JZbaxtYYuIH95YJk4R/XZ+hO
O87TtrtwQZNygMMCZW9Uek6kfBuQapo+Vino0UgH8eWz3JVy8OLtlgIXqkX61/6H
GFZTKcyj+wAP2sQrMn1pMFmXEx+Etffp2946XHdUjcXJWjnoeVMlLh/7XA4nF9ur
hntdKQW3PGGKya+6rA==
=Hz7z
-----END PGP MESSAGE-----`

var privateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lQPGBF0Tpe0BCADm+ja4vMKuodkQEhLm/092M/6gt4TaKwzv8QcA53/FrM3g8wab
oksgIN1T+CscKXOY9GeJ530sBZgu9kTsMeQW3Uf76smo2CV1W7kSTMU+XE5ExGET
+LhkKeHpXoLfZNegKuzH1Qo7DGDOByVrnijbZIukonGwvC/MTduxb69ub+YRhWJc
fCjpMhm4WsC4h0Oz3ir5kx6NsN7XGVT5ghR9OEV6jlFmJ1nYYQxMlBGiATN5f2VR
Y/T9QBLOEsLNvK4OqviLVvgPTQZBePoCeL73CxTbqVhcamvFRVicivl8AphDLATn
1HlIjsTtbH5I/STb8UUdL+4ziRzsQukEw++xABEBAAH+BwMCgg+SBD0Y7LHmqHqo
tQNJrhXRgflQyO4rApMl7dCsilQXPKOd2N85hJbg08PaIaD4dXIylaLF/SRVl5Cw
Mbleqjw/ZNQLmJnTm/diQmTJKXLhsiHS5Cd7nV+KIMwwVX96TCczPqw0i5f2c1p4
tplhJcqEMDA1uOhtALKXLTS3MUBIJV9izj+3HZFAngEJcTZnr8Jq7juEWXxdiSfA
xen3gw6PlfNSvQDQa+D+AH1/k0mpgf07xMUrOVCCUNQJpPKqVWqeNYXGVujcHqD2
FG4CK/lwB3jyVqLJyWsGH359Knhhbhdx879wFY6cldVqvHWk2wFYhzda+As8sJZ4
A1Eyd38uwUBatszAR23ngaMQR3Lc3A/4LS6ahC4QbMtBYHM5Wse1EqD+pFnQs+cP
qPLhuRnMPggYqr1DQYTL9b/f90zq2DW4ZKacG2rNdbTRvzmfWRdRzuhe+jg+8fVe
1sa/BXNbi9JnvVunFxViKVtwdLorBklnJ/wxXpPNILX2EEXC5/Rn8DSPQPX/hJqN
ObL8hE5HQWU/6jhudxvRQM87ebfvGoNOO+ws5HsrbWqS8sgPW/G/BYO429B86Y+q
UY6CB1z/UtImogV6D6+nfUk9rcWRxdB0FcQqE0WlMWXB0lKzV1yiQQCZTDBdhqb4
oVsHe7ugm9E2pz/0lAI11zyctLCqApC1wsjTHqyUPhTffm4UPlBBQg1JK+ksqVrb
CyLvIgx9sLaicMFhL/askReu44jzofuGeTxZrsdzfycgHzFhnjMaQN5/nkSQ41m7
r79VPVSLzXG/XTT4Yf1X8kXX6Sbs2TYn8sWs+Dq/xkebRc9oFVnOg3k890j1Eihx
+/3KbwyxnxQEFtcbIOGmt46UKpYI0mI3EFhRUB6nZWA9wcahIctFMdsMoeR+a/N2
EiINAZbYwpI7tFhUZXN0IENsaWVudCBQcmVwYWdvIChMbGF2ZSBkZSBjbGllbnRl
IHV0aWxpemFkYSBlbiB0ZXN0IGF1dG9tYXRpemFkb3MpIDxjbGllbnRAdGVzdC5j
b20+iQFOBBMBCAA4FiEEjO0uILc5+F8M/RB/gdA542JdgXAFAl0Tpe0CGwMFCwkI
BwIGFQoJCAsCBBYCAwECHgECF4AACgkQgdA542JdgXCNRwf/eGLbWMMBA2Hmg+dY
F/UGph9g7GsgKj7CshB5oLCXSXAitu7D2xI6yN4PLCs3tmhuoT4GPhYy6f7Al1ms
rfDdcDe1O4JxQrtnLM8pMkyjME7mbNOsOSxFllmRt1nG1VOBHTVTdLAmK9Tn4EIi
PQk+/x+R2TNdpubuEIMPvQhcjAW/bD4zMCgTB50C5KfydBZosuSk3WS/qNvJX7bQ
DiQ4PmUwobNC1p72QqyyqriJF+7oCPOYmZXnoWhVl+QcfcPQ9OrhEWxZVsZaJ0fe
GgPaF/a413GjWXg0UqR6oeSZUzEq1109ZC1TS2YngYQNN93jWj8DBbisgJZ1QVfX
f0M+4J0DxgRdE6XtAQgA9y91os2/Fx0AG1Fz6lHuFHN2KUQl6/9cJCHu2rQyD9GO
+LsXpJRzDxYcTvvKQS/2w64fuKI3Yw1vEbhN7YEkw6eSceGBt9nR8KaE2dZ/TfBX
OfDGN847t59idzfOrzZEk/6g8yhH+0lH4rvihNMd/lNEFKLLS/YlSV2uM4PrXtMk
6grfCMxm0OoOqgjcW22/W2YvsQ3ZfM93/vqGCDIWpIsbsIA7FjG5Wyx+8hNIJDMx
D+T+QtTLEe08ta7Si+kT7D76mwl44qiNsoka8ABRF9c0IamaxUclZMzNbkERqhVf
SAw6MCuOJMXs7pkuySxYK2c60BWNKDoac6Da1sZGpQARAQAB/gcDAtrcLO888FSk
5gmauOr9eoV47yng0XL5MQNzu94y+pXNqfLSY+kab8oTLzv8pXv3pQF6HR9mYipM
vwhH4G0wZ6uta70KWdIzTwHMQTRZKqa+rSRqVSk5WkGrzC07lyEuX8CdeWDpvz08
FGIj2mbGmoPyufOuVOqsMdWSUKtR2HOlpqxGWwe6hj8kouvdC8g8ZoQSII7Fd/6C
IiOwUrxiMeyF6g2aMUsp/r3O4hKKlNguRKsziu1kYcoIkVkdsDptD9q+a7ZKSk/+
xjpq1yaQpqn2hrvhPgar2tWvyRcNnnbyb3L/nbgCCKvwTo0sdidjwFCz/3KxzX6L
jflB59fwu61Ms82Xc5oAWgRTISed6jxNCHAC7c48BkV5p9MLrhCgrqKYcSXyEcZE
s6W74vGfftK0150MnMRyKpjwrxerBuCK2LUbucm3lgyNJDkAEt7Nq8mv7tqiH4Yp
Iy7F70hGyfuQvC1a8PIhROoB17OKXNyqUnWhgiAivUkMS8IcKRPRfYGROwY7+zax
dNeH7PhgQN4s+mWXuqj70CJzs5M9u8z65YyPBQkQnNnpoXg72oLxUw3n6ecFiHN2
S0lrtQ1qrYIDKyodCwnTRhF0bx8c2NRQoCSKqmYPoCVJKbW6VivyoF88B50eXIxF
J1t02lkQvHs8xtVSe7Xz4WyxF38DD9utt4iyUk3IRu9+XP6N/fk6Yv8iIKuINQbr
2a3B6DjUJrqVWL62di9suxDII01+klvGYSM/8AFJxghM8YkJf34d8SbeLsc3fh6p
sKW4WJQ9+Av4tiI/wiJRD2HeXkmFPBVuhICCoFZCql4SRfXZLqTLeHo54AWM62Go
YOh5jwOx7XH1lAwqTSDDshdgHXloxcuLW9ohPzOjos/mRObHLaVCzIYs4/O8w8XW
zEYzkdJi9eilyPITNIkBNgQYAQgAIBYhBIztLiC3OfhfDP0Qf4HQOeNiXYFwBQJd
E6XtAhsMAAoJEIHQOeNiXYFweVwH/jkhKVTwWOnQl7CllXmAuPZoTEPDMkeGNmKh
rLRL4VLuNK7dDt+aHUgNB2TqTT76/fViEwm3/3pbhygfeEEEy5T6cIzgR3qD1MCW
FJBFB3ENjZthIedg/jAtnUkwHdIv28Sx9RL4z41hLpXGRpWjiinAzoAwHGgV9CP7
jUWzk5WSTrw7p/hF3Ycid3QOcZAm9MUXWINNG89u2ZTuETTzzLGkaQe514u2dqyp
dJmM+fNpXSDjKMpeWxlgNLw9zIVJ+GjUVfsgew/ALE9lwSpxFRrqpDonlf0H83T0
3SIPibrk16hzsMER2/OAr0hQynAbk3S37Sl9YuGzwBl0zETtFs8=
=yXPi
-----END PGP PRIVATE KEY BLOCK-----`

var publicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBF0Tpe0BCADm+ja4vMKuodkQEhLm/092M/6gt4TaKwzv8QcA53/FrM3g8wab
oksgIN1T+CscKXOY9GeJ530sBZgu9kTsMeQW3Uf76smo2CV1W7kSTMU+XE5ExGET
+LhkKeHpXoLfZNegKuzH1Qo7DGDOByVrnijbZIukonGwvC/MTduxb69ub+YRhWJc
fCjpMhm4WsC4h0Oz3ir5kx6NsN7XGVT5ghR9OEV6jlFmJ1nYYQxMlBGiATN5f2VR
Y/T9QBLOEsLNvK4OqviLVvgPTQZBePoCeL73CxTbqVhcamvFRVicivl8AphDLATn
1HlIjsTtbH5I/STb8UUdL+4ziRzsQukEw++xABEBAAG0WFRlc3QgQ2xpZW50IFBy
ZXBhZ28gKExsYXZlIGRlIGNsaWVudGUgdXRpbGl6YWRhIGVuIHRlc3QgYXV0b21h
dGl6YWRvcykgPGNsaWVudEB0ZXN0LmNvbT6JAU4EEwEIADgWIQSM7S4gtzn4Xwz9
EH+B0DnjYl2BcAUCXROl7QIbAwULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRCB
0DnjYl2BcI1HB/94YttYwwEDYeaD51gX9QamH2DsayAqPsKyEHmgsJdJcCK27sPb
EjrI3g8sKze2aG6hPgY+FjLp/sCXWayt8N1wN7U7gnFCu2cszykyTKMwTuZs06w5
LEWWWZG3WcbVU4EdNVN0sCYr1OfgQiI9CT7/H5HZM12m5u4Qgw+9CFyMBb9sPjMw
KBMHnQLkp/J0Fmiy5KTdZL+o28lfttAOJDg+ZTChs0LWnvZCrLKquIkX7ugI85iZ
leehaFWX5Bx9w9D06uERbFlWxlonR94aA9oX9rjXcaNZeDRSpHqh5JlTMSrXXT1k
LVNLZieBhA033eNaPwMFuKyAlnVBV9d/Qz7guQENBF0Tpe0BCAD3L3Wizb8XHQAb
UXPqUe4Uc3YpRCXr/1wkIe7atDIP0Y74uxeklHMPFhxO+8pBL/bDrh+4ojdjDW8R
uE3tgSTDp5Jx4YG32dHwpoTZ1n9N8Fc58MY3zju3n2J3N86vNkST/qDzKEf7SUfi
u+KE0x3+U0QUostL9iVJXa4zg+te0yTqCt8IzGbQ6g6qCNxbbb9bZi+xDdl8z3f+
+oYIMhakixuwgDsWMblbLH7yE0gkMzEP5P5C1MsR7Ty1rtKL6RPsPvqbCXjiqI2y
iRrwAFEX1zQhqZrFRyVkzM1uQRGqFV9IDDowK44kxezumS7JLFgrZzrQFY0oOhpz
oNrWxkalABEBAAGJATYEGAEIACAWIQSM7S4gtzn4Xwz9EH+B0DnjYl2BcAUCXROl
7QIbDAAKCRCB0DnjYl2BcHlcB/45ISlU8Fjp0JewpZV5gLj2aExDwzJHhjZioay0
S+FS7jSu3Q7fmh1IDQdk6k0++v31YhMJt/96W4coH3hBBMuU+nCM4Ed6g9TAlhSQ
RQdxDY2bYSHnYP4wLZ1JMB3SL9vEsfUS+M+NYS6VxkaVo4opwM6AMBxoFfQj+41F
s5OVkk68O6f4Rd2HInd0DnGQJvTFF1iDTRvPbtmU7hE088yxpGkHudeLtnasqXSZ
jPnzaV0g4yjKXlsZYDS8PcyFSfho1FX7IHsPwCxPZcEqcRUa6qQ6J5X9B/N09N0i
D4m65Neoc7DBEdvzgK9IUMpwG5N0t+0pfWLhs8AZdMxE7RbP
=kbtq
-----END PGP PUBLIC KEY BLOCK-----`

var signed = `-----BEGIN PGP SIGNATURE-----

wsBcBAABCAAQBQJdJLrXCRCB0DnjYl2BcAAAk8UIADTn6wF4KwOLZ9HV26QhWoqf
NMf815VILfdk2wzBSlTg5kvHvhRF5p0dxmUiJKHPNGhyMGbecnmMC09EBb5lvh3g
b9BbZxUfEgDR6JVBtJAXb+l1nilEvEcxXTn87ccuZBsZuKD4A+6Dhs8VJ4faTv7M
w2QWcxIUjEVjFWcV1vbhsfLPm/UA2rkvKFkuORmHz7aG1FpEIRrVuouusqqdhal0
AQfFb3JgS9WTqVd1BLGItoeVHS9gTloJrf1rOON6mq3G0TurBtcK86EBeETbg4Yw
s9nAZmdI3qERI21Uz/AXHKtG/0vKdRep1mOaVOjR4tIVFIYS1NfBkmxUu0yT68w=
=Tua5
-----END PGP SIGNATURE-----`

var privateKeyECC = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: openpgp-mobile

xVgEY1j9rBYJKwYBBAHaRw8BAQdAk3jWTLSrUqL+vyeEv63DTLlp03IcMExucmFE
RG+IbZgAAQDgQazOcCioSeZWQ16Vn/TMYiAgXgsAlL5b5NZWgyTNzA/+zSFUZXN0
IChzYW1wbGUpIDxzYW1wbGVAc2FtcGxlLmNvbT7CiwQTFggAPQUCY1j9rAmQCUTp
H7mMc3UWIQSDHOWl4MeCw6GJdvkJROkfuYxzdQIbAwIeAQIZAQILBwIVCAMWAAIC
IgEAAKj5AP4x9KvZFpriLd2K97CaZs5Mzb4r4jeL/q0pMV6d6SvJ+QEAtrqfQovO
hEtadCopy1R3gepIdeX4Fh7tHNYi3pOO5wjHXQRjWP2sEgorBgEEAZdVAQUBAQdA
j48HXuKTfojSYLslNmAtCj6MkwFpj4TR2b5KkKD29kgDAQoJAAD/SulDoAyVe/VR
6dY5Xe887TZSOCKCk5KNTzBtfMj0nhAQzMJ4BBgWCAAqBQJjWP2sCZAJROkfuYxz
dRYhBIMc5aXgx4LDoYl2+QlE6R+5jHN1AhsMAAB0gAEAz9sGgXtTsfJiEMZhKNj8
XAbymYPQCrsmEBea1uqbB8UA/iKqk0cOabVYTzwBA53G0Tx0C67Xqy46mAtR+W4O
CfMK
=CJ/U
-----END PGP PRIVATE KEY BLOCK-----`

var publicKeyECC = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: openpgp-mobile

xjMEY1j9rBYJKwYBBAHaRw8BAQdAk3jWTLSrUqL+vyeEv63DTLlp03IcMExucmFE
RG+IbZjNIVRlc3QgKHNhbXBsZSkgPHNhbXBsZUBzYW1wbGUuY29tPsKLBBMWCAA9
BQJjWP2sCZAJROkfuYxzdRYhBIMc5aXgx4LDoYl2+QlE6R+5jHN1AhsDAh4BAhkB
AgsHAhUIAxYAAgIiAQAAqPkA/jH0q9kWmuIt3Yr3sJpmzkzNviviN4v+rSkxXp3p
K8n5AQC2up9Ci86ES1p0KinLVHeB6kh15fgWHu0c1iLek47nCM44BGNY/awSCisG
AQQBl1UBBQEBB0CPjwde4pN+iNJguyU2YC0KPoyTAWmPhNHZvkqQoPb2SAMBCgnC
eAQYFggAKgUCY1j9rAmQCUTpH7mMc3UWIQSDHOWl4MeCw6GJdvkJROkfuYxzdQIb
DAAAdIABAM/bBoF7U7HyYhDGYSjY/FwG8pmD0Aq7JhAXmtbqmwfFAP4iqpNHDmm1
WE88AQOdxtE8dAuu16suOpgLUfluDgnzCg==
=oWIw
-----END PGP PUBLIC KEY BLOCK-----`

var passphrase = "test"
var inputMessage = "hola mundo"

func TestFastOpenPGP_Complete(t *testing.T) {

	openPGP := NewFastOpenPGP()
	input, err := openPGP.Encrypt(inputMessage, publicKey, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	output, err := openPGP.Decrypt(input, privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output:", output)

	if output != inputMessage {
		t.Fatal(errors.New("fail"))
	}
}

func TestFastOpenPGP_VerifyAndSign(t *testing.T) {

	openPGP := NewFastOpenPGP()
	input, err := openPGP.Sign(inputMessage, privateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	output, err := openPGP.Verify(input, inputMessage, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output:", output)
}

func TestFastOpenPGP_GenerateComplete(t *testing.T) {
	options := &Options{
		Email:      "sample@sample.com",
		Name:       "Test",
		Comment:    "sample",
		Passphrase: "test",
		KeyOptions: &KeyOptions{
			CompressionLevel: 9,
			RSABits:          2048,
			Cipher:           "aes256",
			Compression:      "none",
			Hash:             "sha512",
		},
	}
	openPGP := NewFastOpenPGP()

	// Generate
	keyPair, err := openPGP.Generate(options)
	if err != nil {
		t.Fatal(err)
	}

	// Common
	input := "hello world"
	passphrase := options.Passphrase

	// Encrypt and Decrypt
	encrypted, err := openPGP.Encrypt(input, keyPair.PublicKey, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := openPGP.Decrypt(encrypted, keyPair.PrivateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}

	if decrypted != input {
		t.Fatal(errors.New("fail decrypt"))
	}
	t.Logf("%s === %s", input, decrypted)

	// Sign and Verify
	signed, err := openPGP.Sign(input, keyPair.PrivateKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := openPGP.Verify(signed, input, keyPair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if verified == false {
		t.Fatal(errors.New("fail verify"))
	}

	t.Logf("verified  == %t", verified)

	// Symmetric
	encryptedSymmetric, err := openPGP.EncryptSymmetric(input, passphrase, nil, options.KeyOptions)
	if err != nil {
		t.Fatal(err)
	}
	decryptedSymmetric, err := openPGP.DecryptSymmetric(encryptedSymmetric, passphrase, options.KeyOptions)
	if err != nil {
		t.Fatal(err)
	}
	if decryptedSymmetric != input {
		t.Fatal(errors.New("fail decrypt symmectric"))
	}
	t.Logf("%s === %s", input, decryptedSymmetric)

}
