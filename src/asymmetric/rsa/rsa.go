package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/illikainen/go-cryptor/src/cryptor"

	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
)

type PublicKey struct {
	key         rsa.PublicKey
	fingerprint string
	purpose     int
}

type PrivateKey struct {
	key         *rsa.PrivateKey
	fingerprint string
	purpose     int
}

const (
	KeySize       = 4096
	SignatureSize = KeySize / 8
)

var publicKeyType = map[int]string{
	cryptor.SignPurpose:    "RSA PUBLIC SIGN KEY",
	cryptor.EncryptPurpose: "RSA PUBLIC ENCRYPT KEY",
}

var privateKeyType = map[int]string{
	cryptor.SignPurpose:    "RSA PRIVATE SIGN KEY",
	cryptor.EncryptPurpose: "RSA PRIVATE ENCRYPT KEY",
}

func GenerateKey(purpose int) (cryptor.PublicKey, cryptor.PrivateKey, error) {
	_, ok := publicKeyType[purpose]
	if !ok {
		return nil, nil, cryptor.ErrInvalidPurpose
	}

	privRSA, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return nil, nil, err
	}

	fingerprint, err := fingerprintPrivateKey(privRSA)
	if err != nil {
		return nil, nil, err
	}

	pubKey := &PublicKey{
		key:         privRSA.PublicKey,
		fingerprint: fingerprint,
		purpose:     purpose,
	}

	privKey := &PrivateKey{
		key:         privRSA,
		fingerprint: fingerprint,
		purpose:     purpose,
	}
	return pubKey, privKey, nil
}

func LoadPublicKey(data []byte, purpose int) (cryptor.PublicKey, []byte, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, nil, errors.Errorf("PEM decoding error")
	}

	if block.Type != publicKeyType[purpose] {
		return nil, nil, cryptor.ErrInvalidKeyType
	}

	pubRSA, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	fingerprint, err := fingerprintPublicKey(pubRSA)
	if err != nil {
		return nil, nil, err
	}

	return &PublicKey{
		key:         *pubRSA,
		fingerprint: fingerprint,
		purpose:     purpose,
	}, rest, nil
}

func ReadPublicKey(path string, purpose int) (cryptor.PublicKey, error) {
	_, ok := publicKeyType[purpose]
	if !ok {
		return nil, cryptor.ErrInvalidPurpose
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

func fingerprintPublicKey(pubKey *rsa.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	sha256sum := sha256.Sum256(pubBytes)
	blake2ssum := blake2s.Sum256(pubBytes)
	cksum := append(sha256sum[:], blake2ssum[:]...)

	return base64.StdEncoding.EncodeToString(cksum), nil
}

func LoadPrivateKey(data []byte, purpose int) (cryptor.PrivateKey, []byte, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, nil, errors.Errorf("PEM decoding error")
	}

	if block.Type != privateKeyType[purpose] {
		return nil, nil, cryptor.ErrInvalidKeyType
	}

	privRSA, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	err = privRSA.Validate()
	if err != nil {
		return nil, nil, err
	}

	fingerprint, err := fingerprintPrivateKey(privRSA)
	if err != nil {
		return nil, nil, err
	}

	return &PrivateKey{
		key:         privRSA,
		fingerprint: fingerprint,
		purpose:     purpose,
	}, rest, nil
}

func ReadPrivateKey(path string, purpose int) (cryptor.PrivateKey, error) {
	_, ok := privateKeyType[purpose]
	if !ok {
		return nil, cryptor.ErrInvalidPurpose
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

func fingerprintPrivateKey(privKey *rsa.PrivateKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", err
	}

	sha256sum := sha256.Sum256(pubBytes)
	blake2ssum := blake2s.Sum256(pubBytes)
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

	if k.purpose != cryptor.SignPurpose {
		return cryptor.ErrWrongPurpose
	}

	blake2bsum := blake2b.Sum512(message)
	err := rsa.VerifyPSS(&k.key, crypto.BLAKE2b_512, blake2bsum[:], signature, nil)
	if err != nil {
		return err
	}

	return nil
}

func (k *PublicKey) Encrypt(plaintext []byte) (string, error) {
	if k.purpose != cryptor.EncryptPurpose {
		return "", cryptor.ErrWrongPurpose
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &k.key, plaintext, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (k *PublicKey) Export() ([]byte, error) {
	buf := bytes.Buffer{}
	err := pem.Encode(&buf, &pem.Block{
		Type:  publicKeyType[k.purpose],
		Bytes: x509.MarshalPKCS1PublicKey(&k.key),
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
	return "rsa"
}

func (k *PublicKey) String() string {
	return fmt.Sprintf("RSA:%s", k.Fingerprint())
}

func (k *PrivateKey) Sign(message []byte) ([]byte, error) {
	if len(message) <= 0 {
		return nil, iofs.ErrInvalidSize
	}

	if k.purpose != cryptor.SignPurpose {
		return nil, cryptor.ErrWrongPurpose
	}

	// NaCl uses Ed25519 with SHA-512 for signing so we opt for BLAKE2b to
	// avoid using the same family of hash functions for RSA signatures.
	blake2bsum := blake2b.Sum512(message)
	sig, err := rsa.SignPSS(rand.Reader, k.key, crypto.BLAKE2b_512, blake2bsum[:], nil)
	if err != nil {
		return nil, err
	}
	if len(sig) != SignatureSize {
		return nil, cryptor.ErrInvalidSignature
	}

	return sig, nil
}

func (k *PrivateKey) Decrypt(ciphertext string) ([]byte, error) {
	if k.purpose != cryptor.EncryptPurpose {
		return nil, cryptor.ErrWrongPurpose
	}

	cipherbytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptOAEP(sha256.New(), rand.Reader, k.key, cipherbytes, nil)
}

func (k *PrivateKey) Export() ([]byte, error) {
	buf := bytes.Buffer{}
	err := pem.Encode(&buf, &pem.Block{
		Type:  privateKeyType[k.purpose],
		Bytes: x509.MarshalPKCS1PrivateKey(k.key),
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
		return errors.Wrap(cryptor.ErrPathExists, path)
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
	return "rsa"
}

func (k *PrivateKey) String() string {
	return fmt.Sprintf("RSA:%s", k.Fingerprint())
}
