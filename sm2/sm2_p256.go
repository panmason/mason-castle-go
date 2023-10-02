package sm2

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

var initonce sync.Once

var sm2P256 SM2P256Curve

type sm2P256FieldElement [9]uint32
type sm2P256LargeFieldElement [17]uint64

const (
	bottom28Bits = 0xFFFFFFF
	bottom29Bits = 0x1FFFFFFF
)

type SM2P256Curve struct {
	*elliptic.CurveParams
	RInverse, A  *big.Int
	a, b, gx, gy sm2P256FieldElement
}

var sm2P256Params = &elliptic.CurveParams{
	Name:    "sm2p256v1",
	BitSize: 256,
	P:       bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"),
	N:       bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"),
	B:       bigFromHex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"),
	Gx:      bigFromHex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"),
	Gy:      bigFromHex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"),
}

func bigFromHex(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("sm2/elliptic: internal error: invalid encoding")
	}
	return b
}

func initP256() {
	sm2P256.A = bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC")
	sm2P256.RInverse = bigFromHex("7ffffffd80000002fffffffe000000017ffffffe800000037ffffffc80000002")
	sm2P256.CurveParams = sm2P256Params
	sm2P256FromBig(&sm2P256.a, sm2P256.A)
	sm2P256FromBig(&sm2P256.gx, sm2P256.Gx)
	sm2P256FromBig(&sm2P256.gy, sm2P256.Gy)
	sm2P256FromBig(&sm2P256.b, sm2P256.B)
}

func SM2P256() elliptic.Curve {
	initonce.Do(initP256)
	return sm2P256
}

func (c SM2P256Curve) IsOnCurve(X, Y *big.Int) bool {
	var a, x, y, y2, x3 sm2P256FieldElement
	sm2P256FromBig(&x, X)
	sm2P256FromBig(&y, Y)

	sm2P256Square(&x3, &x)   // x3 = x ^ 2
	sm2P256Mul(&x3, &x3, &x) // x3 = x ^ 2 * x
	sm2P256Mul(&a, &c.a, &x) // a = a * x
	sm2P256Add(&x3, &x3, &a)
	sm2P256Add(&x3, &x3, &c.b)

	sm2P256Square(&y2, &y) // y2 = y ^ 2
	return sm2P256ToBig(&x3).Cmp(sm2P256ToBig(&y2)) == 0
}

func (c SM2P256Curve) Params() *elliptic.CurveParams {
	return c.CurveParams
}

func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}

func (c SM2P256Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	var X1, Y1, Z1, X2, Y2, Z2, X3, Y3, Z3 sm2P256FieldElement

	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	sm2P256FromBig(&X1, x1)
	sm2P256FromBig(&Y1, y1)
	sm2P256FromBig(&Z1, z1)
	sm2P256FromBig(&X2, x2)
	sm2P256FromBig(&Y2, y2)
	sm2P256FromBig(&Z2, z2)
	sm2P256PointAdd(&X1, &Y1, &Z1, &X2, &Y2, &Z2, &X3, &Y3, &Z3)
	return sm2P256ToAffine(&X3, &Y3, &Z3)
}

func (c SM2P256Curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	var X1, Y1, Z1 sm2P256FieldElement

	z1 := zForAffine(x1, y1)
	sm2P256FromBig(&X1, x1)
	sm2P256FromBig(&Y1, y1)
	sm2P256FromBig(&Z1, z1)
	sm2P256PointDouble(&X1, &Y1, &Z1, &X1, &Y1, &Z1)
	return sm2P256ToAffine(&X1, &Y1, &Z1)
}

func (c SM2P256Curve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	var X, Y, Z, X1, Y1 sm2P256FieldElement
	sm2P256FromBig(&X1, x1)
	sm2P256FromBig(&Y1, y1)
	scalar := sm2GenrateWNaf(k)
	scalarReversed := WNafReversed(scalar)
	sm2P256ScalarMult(&X, &Y, &Z, &X1, &Y1, scalarReversed)
	return sm2P256ToAffine(&X, &Y, &Z)
}

func (c SM2P256Curve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	var scalarReversed [32]byte
	var X, Y, Z sm2P256FieldElement

	sm2P256GetScalar(&scalarReversed, k)
	sm2P256ScalarBaseMult(&X, &Y, &Z, &scalarReversed)
	return sm2P256ToAffine(&X, &Y, &Z)
}

func sm2P256GetScalar(b *[32]byte, a []byte) {
	var scalarBytes []byte

	n := new(big.Int).SetBytes(a)
	if n.Cmp(sm2P256.N) >= 0 {
		n.Mod(n, sm2P256.N)
		scalarBytes = n.Bytes()
	} else {
		scalarBytes = a
	}
	for i, v := range scalarBytes {
		b[len(scalarBytes)-(1+i)] = v
	}
}

// X = a * R mod P
func sm2P256FromBig(X *sm2P256FieldElement, a *big.Int) {
	x := new(big.Int).Lsh(a, 257)
	x.Mod(x, sm2P256.P)
	for i := 0; i < 9; i++ {
		if bits := x.Bits(); len(bits) > 0 {
			X[i] = uint32(bits[0]) & bottom29Bits
		} else {
			X[i] = 0
		}
		x.Rsh(x, 29)
		i++
		if i == 9 {
			break
		}
		if bits := x.Bits(); len(bits) > 0 {
			X[i] = uint32(bits[0]) & bottom28Bits
		} else {
			X[i] = 0
		}
		x.Rsh(x, 28)
	}
}

// X = r * R mod P
// r = X * R' mod P
func sm2P256ToBig(X *sm2P256FieldElement) *big.Int {
	r, tm := new(big.Int), new(big.Int)
	r.SetInt64(int64(X[8]))
	for i := 7; i >= 0; i-- {
		if (i & 1) == 0 {
			r.Lsh(r, 29)
		} else {
			r.Lsh(r, 28)
		}
		tm.SetInt64(int64(X[i]))
		r.Add(r, tm)
	}
	r.Mul(r, sm2P256.RInverse)
	r.Mod(r, sm2P256.P)
	return r
}
