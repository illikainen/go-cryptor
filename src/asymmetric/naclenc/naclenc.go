package naclenc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/illikainen/go-cryptor/src/cryptor"

	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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

func ReadPublicKey(path string, purpose int) (cryptor.PublicKey, error) {
	if purpose != cryptor.EncryptPurpose {
		return nil, cryptor.ErrWrongPurpose
	}

	buf, err := iofs.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, err := cryptor.DecodePEM(buf)
	if err != nil {
		return nil, err
	}
	if block.Type != publicKeyType {
		return nil, cryptor.ErrInvalidKeyType
	}

	pubBytes := &[32]byte{}
	copy((*pubBytes)[:], block.Bytes)
	pubKey := &PublicKey{key: pubBytes}

	log.Debugf("%s: read %s", path, pubKey)
	return pubKey, nil
}

func ReadPrivateKey(path string, purpose int) (cryptor.PrivateKey, error) {
	if purpose != cryptor.EncryptPurpose {
		return nil, cryptor.ErrWrongPurpose
	}

	buf, err := iofs.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, err := cryptor.DecodePEM(buf)
	if err != nil {
		return nil, err
	}
	if block.Type != privateKeyType {
		return nil, cryptor.ErrInvalidKeyType
	}

	privBytes := &[32]byte{}
	copy((*privBytes)[:], block.Bytes)

	privKey := &PrivateKey{key: privBytes}

	log.Debugf("%s: read %s", path, privKey)
	return privKey, nil
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

func (k *PublicKey) Write(path string) (err error) {
	exists, err := iofs.Exists(path)
	if err != nil {
		return err
	}
	if exists {
		return errors.Wrap(cryptor.ErrPathExists, path)
	}

	log.Infof("%s: writing public key for %s", path, k)

	f, err := os.Create(path) // #nosec G304
	if err != nil {
		return err
	}
	defer errorx.Defer(f.Close, &err)

	err = pem.Encode(f, &pem.Block{
		Type:  publicKeyType,
		Bytes: k.key[:],
	})
	if err != nil {
		return err
	}

	log.Debugf("%s: wrote %s", path, k)
	return nil
}

func (k *PublicKey) Fingerprint() string {
	sha256sum := sha256.Sum256(k.key[:])
	return "SHA256:" + base64.StdEncoding.EncodeToString(sha256sum[:])
}

func (k *PublicKey) Type() string {
	return "nacl"
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

func (k *PrivateKey) Write(path string) (err error) {
	exists, err := iofs.Exists(path)
	if err != nil {
		return err
	}
	if exists {
		return errors.Wrap(cryptor.ErrPathExists, path)
	}

	log.Infof("%s: writing private key for %s", path, k)

	f, err := os.Create(path) // #nosec G304
	if err != nil {
		return err
	}
	defer errorx.Defer(f.Close, &err)

	err = pem.Encode(f, &pem.Block{
		Type:  privateKeyType,
		Bytes: k.key[:],
	})
	if err != nil {
		return err
	}

	log.Debugf("%s: wrote %s", path, k)
	return nil
}

func (k *PrivateKey) Fingerprint() string {
	pubBytes := &[32]byte{}
	curve25519.ScalarBaseMult(pubBytes, k.key)

	return (&PublicKey{key: pubBytes}).Fingerprint()
}

func (k *PrivateKey) Type() string {
	return "nacl"
}

func (k *PrivateKey) String() string {
	return fmt.Sprintf("NaCl:%s", k.Fingerprint())
}
