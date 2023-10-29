package sm2

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"github.com/panmason/mason-castle-go/sm3"
)

var errZeroParam = errors.New("zero parameter")
var one = new(big.Int).SetInt64(1)
var two = new(big.Int).SetInt64(2)

var defaultUID = []byte("1234567812345678")

type SM2PublicKey struct {
	Curve elliptic.Curve
	X, Y  *big.Int
}

type SM2PrivateKey struct {
	PublicKey SM2PublicKey
	D         *big.Int
}

type SM2Cipher struct {
	X, Y *big.Int
	C3   []byte
	C2   []byte
}

type SM2Signurate struct {
	R, S *big.Int
}

func (pub *SM2PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*SM2PublicKey)
	if !ok {
		return false
	}
	return pub.X.Cmp(xx.X) == 0 && pub.Y.Cmp(xx.Y) == 0 && pub.Curve == xx.Curve
}

func (priv *SM2PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

func (priv *SM2PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*SM2PrivateKey)
	if !ok {
		return false
	}
	return priv.PublicKey.Equal(&xx.PublicKey) && priv.D.Cmp(xx.D) == 0
}

func GenerateKeySM2(random io.Reader) (*SM2PrivateKey, error) {
	c := SM2P256()
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err := io.ReadFull(random, b)
	if err != nil {
		return nil, err
	}

	k := new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, two)
	k.Mod(k, n)
	k.Add(k, one)
	priv := new(SM2PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func randFieldElement(c elliptic.Curve, random io.Reader) (k *big.Int, err error) {
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(random, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func intToBytes(x int) []byte {
	var buf = make([]byte, 4)

	binary.BigEndian.PutUint32(buf, uint32(x))
	return buf
}

func kdf(length int, x ...[]byte) ([]byte, bool) {
	var c []byte

	ct := 1
	h := sm3.New()
	for i, j := 0, (length+31)/32; i < j; i++ {
		h.Reset()
		for _, xx := range x {
			h.Write(xx)
		}
		h.Write(intToBytes(ct))
		hash := h.Sum(nil)
		if i+1 == j && length%32 != 0 {
			c = append(c, hash[:length%32]...)
		} else {
			c = append(c, hash...)
		}
		ct++
	}
	for i := 0; i < length; i++ {
		if c[i] != 0 {
			return c, true
		}
	}
	return c, false
}

func Encrypt(random io.Reader, pub *SM2PublicKey, data []byte) (*SM2Cipher, error) {
	c := pub.Curve
	dataLen := len(data)
	ret := &SM2Cipher{}
	for {
		k, err := randFieldElement(c, random)
		if err != nil {
			return nil, err
		}
		x1, y1 := c.ScalarBaseMult(k.Bytes())
		x2, y2 := c.ScalarMult(pub.X, pub.Y, k.Bytes())
		hashBuf := make([]byte, 0)

		x2Buf := x2.Bytes()
		y2Buf := y2.Bytes()
		if n := len(x2Buf); n < 32 {
			x132Len := make([]byte, 32)
			x2Buf = append(x132Len[:32-n], x2Buf...)
		}
		if n := len(y2Buf); n < 32 {
			y132Len := make([]byte, 32)
			y2Buf = append(y132Len[:32-n], y2Buf...)
		}

		hashBuf = append(hashBuf, x2Buf...)
		hashBuf = append(hashBuf, data...)
		hashBuf = append(hashBuf, y2Buf...)
		c3 := sm3Hash(hashBuf)
		ret.C3 = c3
		ret.X = x1
		ret.Y = y1
		keyBlock, ok := kdf(dataLen, x2Buf, y2Buf)
		if !ok {
			continue
		}
		c2 := make([]byte, dataLen)
		for i := 0; i < dataLen; i++ {
			c2[i] = keyBlock[i] ^ data[i]
		}
		ret.C2 = c2
		break

	}

	return ret, nil
}

func Decrypt(priv *SM2PrivateKey, cipher *SM2Cipher) ([]byte, error) {
	c := SM2P256()
	onCurve := c.IsOnCurve(cipher.X, cipher.Y)
	if !onCurve {
		return nil, errors.New("decrypt error, c1 not on curve")
	}
	x2, y2 := c.ScalarMult(cipher.X, cipher.Y, priv.D.Bytes())
	x2Buf := x2.Bytes()
	y2Buf := y2.Bytes()
	if n := len(x2Buf); n < 32 {
		x132Len := make([]byte, 32)
		x2Buf = append(x132Len[:32-n], x2Buf...)
	}
	if n := len(y2Buf); n < 32 {
		y132Len := make([]byte, 32)
		y2Buf = append(y132Len[:32-n], y2Buf...)
	}
	dataLen := len(cipher.C2)
	keyBlock, ok := kdf(dataLen, x2Buf, y2Buf)
	if !ok {
		return nil, errors.New("decrypt error")
	}
	plain := make([]byte, dataLen)
	for i := 0; i < dataLen; i++ {
		plain[i] = keyBlock[i] ^ cipher.C2[i]
	}
	return plain, nil
}

func sm3Hash(data []byte) []byte {
	sm3Hash := sm3.New()
	sm3Hash.Write(data)
	return sm3Hash.Sum(nil)
}

// ZA entl || id || a || b || gx || gy || pubx || puby
func ZA(pub *SM2PublicKey, uid []byte) ([]byte, error) {
	za := sm3.New()
	uidLen := len(uid)
	if uidLen >= 8192 {
		return []byte{}, errors.New("SM2: uid too large")
	}
	entla := uint16(8 * uidLen)
	za.Write([]byte{byte((entla >> 8) & 0xFF)})
	za.Write([]byte{byte(entla & 0xFF)})
	if uidLen > 0 {
		za.Write(uid)
	}
	za.Write(sm2P256ToBig(&sm2P256.a).Bytes())
	za.Write(sm2P256.B.Bytes())
	za.Write(sm2P256.Gx.Bytes())
	za.Write(sm2P256.Gy.Bytes())

	xBuf := pub.X.Bytes()
	yBuf := pub.Y.Bytes()
	if n := len(xBuf); n < 32 {
		z := make([]byte, 32)
		xBuf = append(z[:32-n], xBuf...)
	}
	if n := len(yBuf); n < 32 {
		z := make([]byte, 32)
		yBuf = append(z[:32-n], yBuf...)
	}
	za.Write(xBuf)
	za.Write(yBuf)
	return za.Sum(nil)[:32], nil
}

func Sign(random io.Reader, priv *SM2PrivateKey, msg, uid []byte) (*SM2Signurate, error) {
	hashBytes, err := signHash(&priv.PublicKey, msg, uid)
	if err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(hashBytes)
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, errZeroParam
	}
	var k, r, s *big.Int
	for { // 调整算法细节以实现SM2
		for {
			k, err = randFieldElement(c, random)
			if err != nil {
				return nil, err
			}
			r, _ = priv.PublicKey.Curve.ScalarBaseMult(k.Bytes())
			r.Add(r, e)
			r.Mod(r, N)
			if r.Sign() != 0 {
				if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
					break
				}
			}

		}
		rD := new(big.Int).Mul(priv.D, r)
		s = new(big.Int).Sub(k, rD)
		d1 := new(big.Int).Add(priv.D, one)
		d1Inv := new(big.Int).ModInverse(d1, N)
		s.Mul(s, d1Inv)
		s.Mod(s, N)
		if s.Sign() != 0 {
			break
		}
	}
	return &SM2Signurate{
		R: r,
		S: s,
	}, nil
}

func Verify(pubKey *SM2PublicKey, msg, uid []byte, sign *SM2Signurate) (bool, error) {
	hashBytes, err := signHash(pubKey, msg, uid)
	if err != nil {
		return false, err
	}
	e := new(big.Int).SetBytes(hashBytes)
	c := pubKey.Curve
	N := c.Params().N
	one := new(big.Int).SetInt64(1)
	if sign.R.Cmp(one) < 0 || sign.S.Cmp(one) < 0 {
		return false, errors.New("r or s is one")
	}
	if sign.S.Cmp(N) >= 0 || sign.S.Cmp(N) >= 0 {
		return false, errors.New("r or s illeage")
	}

	t := new(big.Int).Add(sign.R, sign.S)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false, errors.New("sign is zero")
	}
	var x *big.Int
	x1, y1 := c.ScalarBaseMult(sign.S.Bytes())
	x2, y2 := c.ScalarMult(pubKey.X, pubKey.Y, t.Bytes())
	x, _ = c.Add(x1, y1, x2, y2)

	x.Add(x, e)
	x.Mod(x, N)
	return x.Cmp(sign.R) == 0, nil
}

func signHash(pub *SM2PublicKey, msg, uid []byte) ([]byte, error) {
	if len(uid) == 0 {
		uid = defaultUID
	}

	za, err := ZA(pub, uid)
	if err != nil {
		return nil, err
	}
	e, err := msgHash(za, msg)
	if err != nil {
		return nil, err
	}

	return e.Bytes(), nil

}

func msgHash(za, msg []byte) (*big.Int, error) {
	e := sm3.New()
	e.Write(za)
	e.Write(msg)
	return new(big.Int).SetBytes(e.Sum(nil)[:32]), nil
}
