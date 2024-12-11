package cose

import (
	"io"
	"testing"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
	"github.com/veraison/go-cose"
)

type customKeySigner struct {
	alg cose.Algorithm
	key sign.PrivateKey
}

func (ks *customKeySigner) Algorithm() cose.Algorithm {
	return ks.alg
}

func (ks *customKeySigner) Sign(rand io.Reader, content []byte) ([]byte, error) {
	suite := schemes.ByName("ML-DSA-44")
	return suite.Sign(ks.key, content, nil), nil
}

type customKeyVerifier struct {
	alg cose.Algorithm
	key sign.PublicKey
}

func (ks *customKeyVerifier) Algorithm() cose.Algorithm {
	return ks.alg
}

func TestCustomSigner(t *testing.T) {
	const (
		COSE_ALG_ML_DSA_44 = -48
	)
	suite := schemes.ByName("ML-DSA-44")
	var seed [32]byte // zero seed
	pub, priv := suite.DeriveKey(seed[:])
	var ks cose.Signer = &keySigner{
		alg: COSE_ALG_ML_DSA_44,
		key: priv,
	}
	var kv = keyVerifier{
		alg: COSE_ALG_ML_DSA_44,
		key: pub,
	}

	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: COSE_ALG_ML_DSA_44,
			cose.HeaderLabelKeyID:     []byte("key-42"),
		},
	}
	payload = []byte("hello post quantum signatures")
	signature, _ := cose.Sign1(nil, ks, headers, payload, nil)
	var sign1 cose.Sign1Message
	sign1.UnmarshalCBOR(signature)

	var verifier cose.Verifier = &kv
	verify_error := sign1.Verify(nil, verifier)

	if verify_error != nil {
		t.Fatalf("Verification failed")
	} else {
		// fmt.Println(cbor.Diagnose(signature))
		// 18([
		// 	<<{
		//  / alg / 1: -48,
		//  / kid / 4: h'6B65792D3432'}
		//  >>,
		// 	{},
		// 	h'4974...722e',
		// 	h'cb5a...293b'
		// ])
	}
}
