package cose

import (
	"errors"
	"io"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type Header struct {
	Alg cose.Algorithm `cbor:"1,keyasint,omitempty"`
	Kid []byte         `cbor:"4,keyasint,omitempty"`
}

type Sign1Verification struct {
	Header  Header
	Payload []byte
}

type keySigner struct {
	alg cose.Algorithm
	key sign.PrivateKey
}

func (ks *keySigner) Algorithm() cose.Algorithm {
	return ks.alg
}

func (ks *keySigner) Sign(rand io.Reader, content []byte) ([]byte, error) {
	name, _ := AlgorithmToSuite(ks.alg)
	suite := schemes.ByName(name)
	return suite.Sign(ks.key, content, nil), nil
}

type keyVerifier struct {
	alg cose.Algorithm
	key sign.PublicKey
}

func (ks *keyVerifier) Algorithm() cose.Algorithm {
	return ks.alg
}

func (ks *keyVerifier) Verify(content []byte, signature []byte) error {
	name, _ := AlgorithmToSuite(ks.alg)
	suite := schemes.ByName(name)
	valid := suite.Verify(ks.key, content, signature, nil)
	if !valid {
		return errors.New("Signature not from public key")
	}
	return nil
}

func AlgorithmToSuite(alg cose.Algorithm) (string, error) {
	switch alg {
	case ML_DSA_44:
		return "ML-DSA-44", nil
	case ML_DSA_65:
		return "ML-DSA-65", nil
	case ML_DSA_87:
		return "ML-DSA-87", nil
	default:
		return "", errors.New(("Unknown algorithm"))
	}
}

func SuiteToAlgorithm(alg string) (cose.Algorithm, error) {
	switch alg {
	case "ML-DSA-44":
		return ML_DSA_44, nil
	case "ML-DSA-65":
		return ML_DSA_65, nil
	case "ML-DSA-87":
		return ML_DSA_87, nil
	default:
		return 0, errors.New("Unknown algorithm")
	}
}

func deterministicBinaryString(data cbor.RawMessage) (cbor.RawMessage, error) {

	decOpts := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF, // duplicated key not allowed
		IndefLength: cbor.IndefLengthForbidden, // no streaming
		IntDec:      cbor.IntDecConvertSigned,  // decode CBOR uint/int to Go int64
	}
	decMode, _ := decOpts.DecMode()
	if len(data) == 0 {
		return nil, io.EOF
	}
	if data[0]>>5 != 2 { // major type 2: bstr
		return nil, errors.New("cbor: require bstr type")
	}

	// fast path: return immediately if bstr is already deterministic
	if err := decMode.Wellformed(data); err != nil {
		return nil, err
	}
	ai := data[0] & 0x1f
	if ai < 24 {
		return data, nil
	}
	switch ai {
	case 24:
		if data[1] >= 24 {
			return data, nil
		}
	case 25:
		if data[1] != 0 {
			return data, nil
		}
	case 26:
		if data[1] != 0 || data[2] != 0 {
			return data, nil
		}
	case 27:
		if data[1] != 0 || data[2] != 0 || data[3] != 0 || data[4] != 0 {
			return data, nil
		}
	}

	// slow path: convert by re-encoding
	// error checking is not required since `data` has been validataed
	var s []byte
	_ = decMode.Unmarshal(data, &s)
	return cbor.Marshal(s)
}

func ToBeSignedFromSign1(signature []byte) ([]byte, error) {
	var sign1 cose.Sign1Message
	sign1.UnmarshalCBOR(signature)
	var external []byte = nil
	var protected cbor.RawMessage
	protected, err := sign1.Headers.MarshalProtected()
	if err != nil {
		return nil, err
	}
	protected, err = deterministicBinaryString(protected)
	if err != nil {
		return nil, err
	}
	if external == nil {
		external = []byte{}
	}
	sigStructure := []any{
		"Signature1",  // context
		protected,     // body_protected
		external,      // external_aad
		sign1.Payload, // payload
	}
	// create the value ToBeSigned by encoding the Sig_structure to a byte
	// string.
	return cbor.Marshal(sigStructure)
}

func SignatureFromSign1(signature []byte) ([]byte, error) {
	var sign1 cose.Sign1Message
	sign1.UnmarshalCBOR(signature)
	return sign1.Signature, nil
}

func Sign1(private_key []byte, header Header, payload []byte) ([]byte, error) {
	var key AKPKey
	cbor.Unmarshal(private_key, &key)
	var suite sign.Scheme
	name, _ := AlgorithmToSuite(key.Alg)
	suite = schemes.ByName(name)
	_, priv := suite.DeriveKey(key.Priv)
	var signer cose.Signer = &keySigner{
		alg: key.Alg,
		key: priv,
	}
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: header.Alg,
			cose.HeaderLabelKeyID:     header.Kid,
		},
	}
	sign1, _ := cose.Sign1(nil, signer, headers, payload, nil)
	return sign1, nil
}

func VerifySign1(public_key []byte, signature []byte) (Sign1Verification, error) {
	var key AKPKey
	var verified = Sign1Verification{}
	cbor.Unmarshal(public_key, &key)
	name, _ := AlgorithmToSuite(key.Alg)
	suite := schemes.ByName(name)
	pub, _ := suite.UnmarshalBinaryPublicKey(key.Pub)
	var sign1 cose.Sign1Message
	sign1.UnmarshalCBOR(signature)
	var kv = keyVerifier{
		alg: key.Alg,
		key: pub,
	}
	var verifier cose.Verifier = &kv
	verify_error := sign1.Verify(nil, verifier)
	if verify_error != nil {
		return verified, verify_error
	}
	var h []byte
	cbor.Unmarshal(sign1.Headers.RawProtected, &h)
	cbor.Unmarshal(h, &verified.Header)
	verified.Payload = sign1.Payload
	return verified, nil
}
