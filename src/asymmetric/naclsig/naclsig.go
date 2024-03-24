package naclsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/illikainen/go-cryptor/src/cryptor"
	"github.com/illikainen/go-cryptor/src/metadata"

	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/nacl/sign"
	"golang.org/x/crypto/ssh"
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

func ReadPublicKey(path string, purpose int) (cryptor.PublicKey, error) {
	if purpose != cryptor.SignPurpose {
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

	fingerprint, err := fingerprintPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}

	pubKey := &PublicKey{
		key:         pubBytes,
		fingerprint: fingerprint,
	}

	log.Debugf("%s: read %s", path, pubKey)
	return pubKey, nil
}

func fingerprintPublicKey(pubKey *[32]byte) (string, error) {
	pubEd25519 := ed25519.PublicKey((*pubKey)[:])
	sshPubKey, err := ssh.NewPublicKey(pubEd25519)
	if err != nil {
		return "", err
	}

	return ssh.FingerprintSHA256(sshPubKey), nil
}

func ReadPrivateKey(path string, purpose int) (cryptor.PrivateKey, error) {
	if purpose != cryptor.SignPurpose {
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

	privBytes := &[64]byte{}
	copy((*privBytes)[:], block.Bytes)

	fingerprint, err := fingerprintPrivateKey(privBytes)
	if err != nil {
		return nil, err
	}

	privKey := &PrivateKey{
		key:         privBytes,
		fingerprint: fingerprint,
	}

	log.Debugf("%s: read %s", path, privKey)
	return privKey, nil
}

func fingerprintPrivateKey(privKey *[64]byte) (string, error) {
	privEd25519 := ed25519.PrivateKey((*privKey)[:])
	pubEd25519, ok := privEd25519.Public().(ed25519.PublicKey)
	if !ok {
		return "", cryptor.ErrInvalidKeyType
	}

	sshPubKey, err := ssh.NewPublicKey(pubEd25519)
	if err != nil {
		return "", err
	}

	return ssh.FingerprintSHA256(sshPubKey), nil
}

func (k *PublicKey) Verify(message []byte, signature []byte) error {
	if len(signature) != SignatureSize {
		return cryptor.ErrInvalidSignature
	}

	if len(message) != metadata.MetadataSize {
		return iofs.ErrInvalidSize
	}

	sig := append(signature, message...)

	verified, ok := sign.Open(nil, sig, k.key)
	if !ok || len(verified) != len(sig)-sign.Overhead || !bytes.Equal(verified, message) {
		return cryptor.ErrInvalidSignature
	}

	return nil
}

func (k *PublicKey) Encrypt(_ []byte) (string, error) {
	return "", cryptor.ErrNotImplemented
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
	return k.fingerprint
}

func (k *PublicKey) Type() string {
	return "nacl"
}

func (k *PublicKey) String() string {
	return fmt.Sprintf("NaCl:%s", k.Fingerprint())
}

func (k *PrivateKey) Sign(message []byte) ([]byte, error) {
	if len(message) != metadata.MetadataSize {
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

func (k *PrivateKey) Write(path string) (err error) {
	exists, err := iofs.Exists(path)
	if err != nil {
		return err
	}
	if exists {
		return cryptor.ErrPathExists
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
	return k.fingerprint
}

func (k *PrivateKey) Type() string {
	return "nacl"
}

func (k *PrivateKey) String() string {
	return fmt.Sprintf("NaCl:%s", k.Fingerprint())
}
