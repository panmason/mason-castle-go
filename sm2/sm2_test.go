package sm2

import (
	"crypto/rand"
	"testing"
)

func TestSM2EncAndDec(t *testing.T) {
	priv, err := GenerateKeySM2(rand.Reader)
	if err != nil {
		t.Log(err)
		t.Fatal()
	}

	data := []byte("123123123123123123123123123")

	cipher, err := Encrypt(rand.Reader, &priv.PublicKey, data)
	if err != nil {
		t.Log(err)
		t.Fatal()
	}

	plain, err := Decrypt(priv, cipher)
	if err != nil {
		t.Log(err)
		t.Fatal()
	}

	t.Log(string(plain))

}
