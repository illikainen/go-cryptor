package naclsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/illikainen/go-cryptor/src/cryptor"

	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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

func LoadPublicKey(data []byte, _ int) (cryptor.PublicKey, []byte, error) {
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

func ReadPublicKey(path string, purpose int) (cryptor.PublicKey, error) {
	if purpose != cryptor.SignPurpose {
		return nil, cryptor.ErrWrongPurpose
	}

	buf, err := iofs.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pubKey, rest, err := LoadPublicKey(buf, purpose)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, iofs.ErrInvalidSize
	}

	log.Debugf("%s: read %s", path, pubKey)
	return pubKey, nil
}

func fingerprintPublicKey(pubKey *[32]byte) (string, error) {
	sha256sum := sha256.Sum256(pubKey[:])
	blake2ssum := blake2s.Sum256(pubKey[:])
	cksum := append(sha256sum[:], blake2ssum[:]...)
	return base64.StdEncoding.EncodeToString(cksum), nil
}

func LoadPrivateKey(data []byte, _ int) (cryptor.PrivateKey, []byte, error) {
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

func ReadPrivateKey(path string, purpose int) (cryptor.PrivateKey, error) {
	if purpose != cryptor.SignPurpose {
		return nil, cryptor.ErrWrongPurpose
	}

	buf, err := iofs.ReadFile(path)
	if err != nil {
		return nil, err
	}

	privKey, rest, err := LoadPrivateKey(buf, purpose)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, iofs.ErrInvalidSize
	}

	log.Debugf("%s: read %s", path, privKey)
	return privKey, nil
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

func (k *PublicKey) Export() ([]byte, error) {
	buf := bytes.Buffer{}
	err := pem.Encode(&buf, &pem.Block{
		Type:  publicKeyType,
		Bytes: k.key[:],
	})
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (k *PublicKey) Write(path string) error {
	exists, err := iofs.Exists(path)
	if err != nil {
		return err
	}
	if exists {
		return errors.Wrap(cryptor.ErrPathExists, path)
	}

	log.Infof("%s: writing public key for %s", path, k)

	export, err := k.Export()
	if err != nil {
		return err
	}

	err = os.WriteFile(path, export, 0600)
	if err != nil {
		return err
	}

	log.Debugf("%s: wrote %s", path, k)
	return nil
}

func (k *PublicKey) Fingerprint() string {
	return k.fingerprint
}

func (k *PublicKey) Type() string {
	return "nacl"
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

func (k *PrivateKey) Export() ([]byte, error) {
	buf := bytes.Buffer{}
	err := pem.Encode(&buf, &pem.Block{
		Type:  privateKeyType,
		Bytes: k.key[:],
	})
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (k *PrivateKey) Write(path string) error {
	exists, err := iofs.Exists(path)
	if err != nil {
		return err
	}
	if exists {
		return cryptor.ErrPathExists
	}

	log.Infof("%s: writing private key for %s", path, k)

	export, err := k.Export()
	if err != nil {
		return err
	}

	err = os.WriteFile(path, export, 0600)
	if err != nil {
		return err
	}

	log.Debugf("%s: wrote %s", path, k)
	return nil
}

func (k *PrivateKey) Fingerprint() string {
	return k.fingerprint
}

func (k *PrivateKey) Type() string {
	return "nacl"
}

func (k *PrivateKey) String() string {
	return fmt.Sprintf("NaCl:%s", k.Fingerprint())
}
