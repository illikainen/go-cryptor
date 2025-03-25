package cryptor

import (
	"bytes"
	"encoding/pem"

	"github.com/pkg/errors"
)

type PublicKey interface {
	Verify([]byte, []byte) error
	Encrypt([]byte) (string, error)
	UnmarshalJSON([]byte) error
	Write(string) error
	Fingerprint() string
	String() string
}

type PrivateKey interface {
	Sign([]byte) ([]byte, error)
	Decrypt(string) ([]byte, error)
	UnmarshalJSON([]byte) error
	Write(string) error
	Fingerprint() string
	String() string
}

type SymmetricKey interface {
	Encrypt(string, string) error
	Decrypt(string, string) error
	Marshal() ([]byte, error)
}

const (
	UnknownAsymetric = iota
	NaClAsymmetric
	RSAAsymmetric
)

var AsymmetricMap = map[string]int{
	"nacl": NaClAsymmetric,
	"rsa":  RSAAsymmetric,
}

const (
	UnknownSymmetric = iota
	AESGCMSymmetric
	XCHACHA20POLY1305Symmetric
)

var SymmetricMap = map[string]int{
	"aesgcm":            AESGCMSymmetric,
	"xchacha20poly1305": XCHACHA20POLY1305Symmetric,
}

const (
	UnknownKeyType = iota
	PublicKeyType
	PrivateKeyType
)

const (
	UnknownPurpose = iota
	SignPurpose
	EncryptPurpose
)

var ErrInvalidSignature = errors.New("invalid signature")
var ErrInvalidKey = errors.New("invalid key")
var ErrInvalidKeyType = errors.New("invalid key type")
var ErrMultipleKeys = errors.New("multiple keys found in file")
var ErrNotImplemented = errors.New("operation is not implemented for the key type")
var ErrPathExists = errors.New("path already exist")
var ErrInvalidPurpose = errors.New("a key purpose must be specified")
var ErrWrongPurpose = errors.New("key used for the wrong purpose")
var ErrEncrypt = errors.New("encryption failed")
var ErrDecrypt = errors.New("decryption failed")
var ErrMissingPublicKey = errors.New("missing private key")
var ErrMissingPrivateKey = errors.New("missing private key")

func DecodePEM(data []byte) (*pem.Block, error) {
	block, rest := pem.Decode(data)

	if len(rest) != 0 {
		if bytes.Equal(data, rest) {
			return nil, ErrInvalidKey
		}
		return nil, ErrMultipleKeys
	}

	return block, nil
}
