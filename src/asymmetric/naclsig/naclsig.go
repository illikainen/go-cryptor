package naclsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/illikainen/go-cryptor/src/cryptor"

	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/nacl/sign"
)

const (
	publicKeyType  = "NACL PUBLIC SIGN KEY"
	privateKeyType = "NACL PRIVATE SIGN KEY"
)

const SignatureSize = ed25519.SignatureSize

type PublicKey struct {
	key         *[32]byte
	fingerprint string
}

type PrivateKey struct {
	key         *[64]byte
	fingerprint string
}

func GenerateKey(purpose int) (cryptor.PublicKey, cryptor.PrivateKey, error) {
	if purpose != cryptor.SignPurpose {
		return nil, nil, cryptor.ErrWrongPurpose
	}

	pubBytes, privBytes, err := sign.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	fingerprint, err := fingerprintPublicKey(pubBytes)
	if err != nil {
		return nil, nil, err
	}

	pubKey := &PublicKey{
		key:         pubBytes,
		fingerprint: fingerprint,
	}

	privKey := &PrivateKey{
		key:         privBytes,
		fingerprint: fingerprint,
	}

	return pubKey, privKey, nil
}

func LoadPublicKeyLegacy(data []byte, _ int) (cryptor.PublicKey, []byte, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, nil, errors.Errorf("PEM decoding error")
	}

	if block.Type != publicKeyType || len(block.Bytes) != 32 {
		return nil, nil, cryptor.ErrInvalidKeyType
	}

	pubBytes := &[32]byte{}
	copy((*pubBytes)[:], block.Bytes)

	fingerprint, err := fingerprintPublicKey(pubBytes)
	if err != nil {
		return nil, nil, err
	}

	return &PublicKey{
		key:         pubBytes,
		fingerprint: fingerprint,
	}, rest, nil
}

func fingerprintPublicKey(pubKey *[32]byte) (string, error) {
	sha256sum := sha256.Sum256(pubKey[:])
	blake2ssum := blake2s.Sum256(pubKey[:])
	cksum := append(sha256sum[:], blake2ssum[:]...)
	return base64.StdEncoding.EncodeToString(cksum), nil
}

func LoadPrivateKeyLegacy(data []byte, _ int) (cryptor.PrivateKey, []byte, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, nil, errors.Errorf("PEM decoding error")
	}
	if block.Type != privateKeyType || len(block.Bytes) != 64 {
		return nil, nil, cryptor.ErrInvalidKeyType
	}

	privBytes := &[64]byte{}
	copy((*privBytes)[:], block.Bytes)

	fingerprint, err := fingerprintPrivateKey(privBytes)
	if err != nil {
		return nil, nil, err
	}

	return &PrivateKey{
		key:         privBytes,
		fingerprint: fingerprint,
	}, rest, nil
}

func fingerprintPrivateKey(privKey *[64]byte) (string, error) {
	priv := ed25519.PrivateKey((*privKey)[:])
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", cryptor.ErrInvalidKeyType
	}

	sha256sum := sha256.Sum256(pub[:])
	blake2ssum := blake2s.Sum256(pub[:])
	cksum := append(sha256sum[:], blake2ssum[:]...)
	return base64.StdEncoding.EncodeToString(cksum), nil
}

func (k *PublicKey) Verify(message []byte, signature []byte) error {
	if len(message) <= 0 {
		return iofs.ErrInvalidSize
	}

	if len(signature) != SignatureSize {
		return cryptor.ErrInvalidSignature
	}

	sig := []byte{}
	sig = append(sig, signature...)
	sig = append(sig, message...)

	verified, ok := sign.Open(nil, sig, k.key)
	if !ok || len(verified) != len(sig)-sign.Overhead || !bytes.Equal(verified, message) {
		return cryptor.ErrInvalidSignature
	}

	return nil
}

func (k *PublicKey) Encrypt(_ []byte) (string, error) {
	return "", cryptor.ErrNotImplemented
}

func (k *PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(k.key[:]))
}

func (k *PublicKey) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)
	if err != nil {
		return err
	}

	tmp, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}

	key := &[32]byte{}
	if len(tmp) != 32 || copy(key[:], tmp) != 32 {
		return cryptor.ErrInvalidKeyType
	}

	fingerprint, err := fingerprintPublicKey(key)
	if err != nil {
		return err
	}

	k.key = key
	k.fingerprint = fingerprint
	return nil
}

func (k *PublicKey) Write(_ string) error {
	return cryptor.ErrNotImplemented
}

func (k *PublicKey) Fingerprint() string {
	return k.fingerprint
}

func (k *PublicKey) String() string {
	return fmt.Sprintf("NaCl:%s", k.Fingerprint())
}

func (k *PrivateKey) Sign(message []byte) ([]byte, error) {
	if len(message) <= 0 {
		return nil, iofs.ErrInvalidSize
	}

	signature := sign.Sign(nil, message, k.key)
	if len(signature) != len(message)+sign.Overhead {
		return nil, cryptor.ErrInvalidSignature
	}

	sig := signature[:sign.Overhead]
	if len(sig) != SignatureSize {
		return nil, cryptor.ErrInvalidSignature
	}

	return sig, nil
}

func (k *PrivateKey) Decrypt(_ string) ([]byte, error) {
	return nil, cryptor.ErrNotImplemented
}

func (k *PrivateKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(k.key[:]))
}

func (k *PrivateKey) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)
	if err != nil {
		return err
	}

	tmp, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}

	key := &[64]byte{}
	if len(tmp) != 64 || copy(key[:], tmp) != 64 {
		return cryptor.ErrInvalidKeyType
	}

	fingerprint, err := fingerprintPrivateKey(key)
	if err != nil {
		return err
	}

	k.key = key
	k.fingerprint = fingerprint
	return nil
}

func (k *PrivateKey) Write(_ string) error {
	return cryptor.ErrNotImplemented
}

func (k *PrivateKey) Fingerprint() string {
	return k.fingerprint
}

func (k *PrivateKey) String() string {
	return fmt.Sprintf("NaCl:%s", k.Fingerprint())
}
