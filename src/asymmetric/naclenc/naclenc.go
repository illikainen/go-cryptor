package naclenc

import (
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
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

type PublicKey struct {
	key *[32]byte
}

type PrivateKey struct {
	key *[32]byte
}

const (
	publicKeyType  = "NACL PUBLIC ENCRYPT KEY"
	privateKeyType = "NACL PRIVATE ENCRYPT KEY"
)

func GenerateKey(purpose int) (cryptor.PublicKey, cryptor.PrivateKey, error) {
	if purpose != cryptor.EncryptPurpose {
		return nil, nil, cryptor.ErrWrongPurpose
	}

	pubBytes, privBytes, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pubKey := &PublicKey{key: pubBytes}
	privKey := &PrivateKey{key: privBytes}

	return pubKey, privKey, nil
}

func LoadPublicKeyLegacy(data []byte, _ int) (cryptor.PublicKey, []byte, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, nil, errors.Errorf("PEM decoding error")
	}
	if block.Type != publicKeyType {
		return nil, nil, cryptor.ErrInvalidKeyType
	}

	pubBytes := &[32]byte{}
	copy((*pubBytes)[:], block.Bytes)

	return &PublicKey{key: pubBytes}, rest, nil
}

func LoadPrivateKeyLegacy(data []byte, _ int) (cryptor.PrivateKey, []byte, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, nil, errors.Errorf("PEM decoding error")
	}
	if block.Type != privateKeyType {
		return nil, nil, cryptor.ErrInvalidKeyType
	}

	privBytes := &[32]byte{}
	copy((*privBytes)[:], block.Bytes)

	return &PrivateKey{key: privBytes}, rest, nil
}

func (k *PublicKey) Verify(_ []byte, _ []byte) error {
	return cryptor.ErrNotImplemented
}

func (k *PublicKey) Encrypt(plaintext []byte) (string, error) {
	if len(plaintext) >= 1024*4 {
		return "", iofs.ErrInvalidSize
	}

	ciphertext, err := box.SealAnonymous(nil, plaintext, k.key, rand.Reader)
	if err != nil {
		return "", err
	}
	if len(ciphertext) != len(plaintext)+box.AnonymousOverhead {
		return "", cryptor.ErrEncrypt
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
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

	k.key = key
	return nil
}

func (k *PublicKey) Write(_ string) error {
	return cryptor.ErrNotImplemented
}

func (k *PublicKey) Fingerprint() string {
	sha256sum := sha256.Sum256(k.key[:])
	blake2ssum := blake2s.Sum256(k.key[:])
	cksum := append(sha256sum[:], blake2ssum[:]...)
	return base64.StdEncoding.EncodeToString(cksum)
}

func (k *PublicKey) String() string {
	return fmt.Sprintf("NaCl:%s", k.Fingerprint())
}

func (k *PrivateKey) Sign(_ []byte) ([]byte, error) {
	return nil, cryptor.ErrNotImplemented
}

func (k *PrivateKey) Decrypt(ciphertext string) ([]byte, error) {
	pubKey := &[32]byte{}
	curve25519.ScalarBaseMult(pubKey, k.key)

	cipherbytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	plaintext, ok := box.OpenAnonymous(nil, cipherbytes, pubKey, k.key)
	if !ok || len(plaintext) != len(cipherbytes)-box.AnonymousOverhead {
		return nil, cryptor.ErrDecrypt
	}

	return plaintext, nil
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

	key := &[32]byte{}
	if len(tmp) != 32 || copy(key[:], tmp) != 32 {
		return cryptor.ErrInvalidKeyType
	}

	k.key = key
	return nil
}

func (k *PrivateKey) Write(_ string) error {
	return cryptor.ErrNotImplemented
}

func (k *PrivateKey) Fingerprint() string {
	pubBytes := &[32]byte{}
	curve25519.ScalarBaseMult(pubBytes, k.key)

	return (&PublicKey{key: pubBytes}).Fingerprint()
}

func (k *PrivateKey) String() string {
	return fmt.Sprintf("NaCl:%s", k.Fingerprint())
}
