// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package model

import "strconv"

type Curve int32

const (
	CurveCURVE25519    Curve = 0
	CurveCURVE448      Curve = 1
	CurveP256          Curve = 2
	CurveP384          Curve = 3
	CurveP521          Curve = 4
	CurveSECP256K1     Curve = 5
	CurveBRAINPOOLP256 Curve = 6
	CurveBRAINPOOLP384 Curve = 7
	CurveBRAINPOOLP512 Curve = 8
)

var EnumNamesCurve = map[Curve]string{
	CurveCURVE25519:    "CURVE25519",
	CurveCURVE448:      "CURVE448",
	CurveP256:          "P256",
	CurveP384:          "P384",
	CurveP521:          "P521",
	CurveSECP256K1:     "SECP256K1",
	CurveBRAINPOOLP256: "BRAINPOOLP256",
	CurveBRAINPOOLP384: "BRAINPOOLP384",
	CurveBRAINPOOLP512: "BRAINPOOLP512",
}

var EnumValuesCurve = map[string]Curve{
	"CURVE25519":    CurveCURVE25519,
	"CURVE448":      CurveCURVE448,
	"P256":          CurveP256,
	"P384":          CurveP384,
	"P521":          CurveP521,
	"SECP256K1":     CurveSECP256K1,
	"BRAINPOOLP256": CurveBRAINPOOLP256,
	"BRAINPOOLP384": CurveBRAINPOOLP384,
	"BRAINPOOLP512": CurveBRAINPOOLP512,
}

func (v Curve) String() string {
	if s, ok := EnumNamesCurve[v]; ok {
		return s
	}
	return "Curve(" + strconv.FormatInt(int64(v), 10) + ")"
}
