package asymmetric

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/illikainen/go-cryptor/src/asymmetric/nacl"
	"github.com/illikainen/go-cryptor/src/asymmetric/naclsig"
	"github.com/illikainen/go-cryptor/src/asymmetric/rsa"
	"github.com/illikainen/go-cryptor/src/cryptor"

	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/blake2s"
)

const SignatureSize = naclsig.SignatureSize + rsa.SignatureSize

type PublicKeyContainer struct {
	naclSign cryptor.PublicKey
	naclEnc  cryptor.PublicKey
	rsaSign  cryptor.PublicKey
	rsaEnc   cryptor.PublicKey
}

type PrivateKeyContainer struct {
	naclSign cryptor.PrivateKey
	naclEnc  cryptor.PrivateKey
	rsaSign  cryptor.PrivateKey
	rsaEnc   cryptor.PrivateKey
}

func GenerateKey(delay time.Duration) (cryptor.PublicKey, cryptor.PrivateKey, error) {
	log.Debugf("generating NaCl signing key...")
	naclSignPub, naclSignPriv, err := nacl.GenerateKey(cryptor.SignPurpose)
	if err != nil {
		return nil, nil, err
	}
	log.Debugf("NaCl signature fingerprint: %s", naclSignPub.Fingerprint())
	time.Sleep(delay)

	log.Debugf("generating NaCl encryption key...")
	naclEncPub, naclEncPriv, err := nacl.GenerateKey(cryptor.EncryptPurpose)
	if err != nil {
		return nil, nil, err
	}
	log.Debugf("NaCl encryption fingerprint: %s", naclEncPub.Fingerprint())
	time.Sleep(delay)

	log.Debugf("generating RSA signing key...")
	rsaSignPub, rsaSignPriv, err := rsa.GenerateKey(cryptor.SignPurpose)
	if err != nil {
		return nil, nil, err
	}
	log.Debugf("RSA signature fingerprint: %s", rsaSignPub.Fingerprint())
	time.Sleep(delay)

	log.Debugf("generating RSA encryption key...")
	rsaEncPub, rsaEncPriv, err := rsa.GenerateKey(cryptor.EncryptPurpose)
	if err != nil {
		return nil, nil, err
	}
	log.Debugf("RSA encryption fingerprint: %s", rsaEncPub.Fingerprint())

	pub := &PublicKeyContainer{
		naclSign: naclSignPub,
		naclEnc:  naclEncPub,
		rsaSign:  rsaSignPub,
		rsaEnc:   rsaEncPub,
	}
	priv := &PrivateKeyContainer{
		naclSign: naclSignPriv,
		naclEnc:  naclEncPriv,
		rsaSign:  rsaSignPriv,
		rsaEnc:   rsaEncPriv,
	}
	return pub, priv, nil
}

func ReadPublicKey(path string) (cryptor.PublicKey, error) {
	log.Tracef("%s: read public key", path)

	buf, err := iofs.ReadFile(path)
	if err != nil {
		return nil, err
	}

	naclSignPub, rest, err := nacl.LoadPublicKey(buf, cryptor.SignPurpose)
	if err != nil {
		return nil, err
	}

	naclEncPub, rest, err := nacl.LoadPublicKey(rest, cryptor.EncryptPurpose)
	if err != nil {
		return nil, err
	}

	rsaSignPub, rest, err := rsa.LoadPublicKey(rest, cryptor.SignPurpose)
	if err != nil {
		return nil, err
	}

	rsaEncPub, rest, err := rsa.LoadPublicKey(rest, cryptor.EncryptPurpose)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.Errorf("invalid size")
	}

	pub := &PublicKeyContainer{
		naclSign: naclSignPub,
		naclEnc:  naclEncPub,
		rsaSign:  rsaSignPub,
		rsaEnc:   rsaEncPub,
	}
	return pub, nil
}

func ReadPrivateKey(path string) (cryptor.PrivateKey, error) {
	log.Tracef("%s: read private key", path)

	buf, err := iofs.ReadFile(path)
	if err != nil {
		return nil, err
	}

	naclSignPriv, rest, err := nacl.LoadPrivateKey(buf, cryptor.SignPurpose)
	if err != nil {
		return nil, err
	}

	naclEncPriv, rest, err := nacl.LoadPrivateKey(rest, cryptor.EncryptPurpose)
	if err != nil {
		return nil, err
	}

	rsaSignPriv, rest, err := rsa.LoadPrivateKey(rest, cryptor.SignPurpose)
	if err != nil {
		return nil, err
	}

	rsaEncPriv, rest, err := rsa.LoadPrivateKey(rest, cryptor.EncryptPurpose)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.Errorf("invalid size")
	}

	priv := &PrivateKeyContainer{
		naclSign: naclSignPriv,
		naclEnc:  naclEncPriv,
		rsaSign:  rsaSignPriv,
		rsaEnc:   rsaEncPriv,
	}
	return priv, nil
}

func (k *PublicKeyContainer) Verify(message []byte, signature []byte) error {
	err := k.naclSign.Verify(message, signature[:naclsig.SignatureSize])
	if err != nil {
		return err
	}
	log.Infof("metadata verified by %s", k.naclSign.String())

	err = k.rsaSign.Verify(message, signature[naclsig.SignatureSize:])
	if err != nil {
		return err
	}
	log.Infof("metadata verified by %s", k.rsaSign.String())

	return nil
}

func (k *PublicKeyContainer) Encrypt(plaintext []byte) (string, error) {
	partial, err := k.naclEnc.Encrypt(plaintext)
	if err != nil {
		return "", err
	}

	ciphertext, err := k.rsaEnc.Encrypt([]byte(partial))
	if err != nil {
		return "", err
	}

	return ciphertext, err
}

func (k *PublicKeyContainer) Export() ([]byte, error) {
	buf := bytes.Buffer{}

	for _, key := range []cryptor.PublicKey{k.naclSign, k.naclEnc, k.rsaSign, k.rsaEnc} {
		data, err := key.Export()
		if err != nil {
			return nil, err
		}

		n, err := buf.Write(data)
		if err != nil {
			return nil, err
		}
		if n != len(data) {
			return nil, errors.Errorf("invalid size")
		}
	}

	return buf.Bytes(), nil
}

func (k *PublicKeyContainer) Write(path string) error {
	exists, err := iofs.Exists(path)
	if err != nil {
		return err
	}
	if exists {
		return errors.Wrap(cryptor.ErrPathExists, path)
	}

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

func (k *PublicKeyContainer) Fingerprint() string {
	fingerprints := []string{
		k.naclSign.Fingerprint(),
		k.naclEnc.Fingerprint(),
		k.rsaSign.Fingerprint(),
		k.rsaEnc.Fingerprint(),
	}
	sha256sum := sha256.Sum256([]byte(strings.Join(fingerprints, "")))
	blake2ssum := blake2s.Sum256([]byte(strings.Join(fingerprints, "")))
	cksum := append(sha256sum[:], blake2ssum[:]...)

	return base64.StdEncoding.EncodeToString(cksum)
}

func (k *PublicKeyContainer) Type() string {
	return "nacl+rsa"
}

func (k *PublicKeyContainer) String() string {
	return fmt.Sprintf("NaCl+RSA:%s", k.Fingerprint())
}

func (k *PrivateKeyContainer) Sign(message []byte) ([]byte, error) {
	naclSig, err := k.naclSign.Sign(message)
	if err != nil {
		return nil, err
	}

	rsaSig, err := k.rsaSign.Sign(message)
	if err != nil {
		return nil, err
	}

	return append(naclSig, rsaSig...), nil
}

func (k *PrivateKeyContainer) Decrypt(ciphertext string) ([]byte, error) {
	partial, err := k.rsaEnc.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	plaintext, err := k.naclEnc.Decrypt(string(partial))
	if err != nil {
		return nil, err
	}

	return plaintext, err
}

func (k *PrivateKeyContainer) Export() ([]byte, error) {
	buf := bytes.Buffer{}

	for _, key := range []cryptor.PrivateKey{k.naclSign, k.naclEnc, k.rsaSign, k.rsaEnc} {
		data, err := key.Export()
		if err != nil {
			return nil, err
		}

		n, err := buf.Write(data)
		if err != nil {
			return nil, err
		}
		if n != len(data) {
			return nil, errors.Errorf("invalid size")
		}
	}

	return buf.Bytes(), nil
}

func (k *PrivateKeyContainer) Write(path string) error {
	exists, err := iofs.Exists(path)
	if err != nil {
		return err
	}
	if exists {
		return errors.Wrap(cryptor.ErrPathExists, path)
	}

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

func (k *PrivateKeyContainer) Fingerprint() string {
	fingerprints := []string{
		k.naclSign.Fingerprint(),
		k.naclEnc.Fingerprint(),
		k.rsaSign.Fingerprint(),
		k.rsaEnc.Fingerprint(),
	}
	sha256sum := sha256.Sum256([]byte(strings.Join(fingerprints, "")))
	blake2ssum := blake2s.Sum256([]byte(strings.Join(fingerprints, "")))
	cksum := append(sha256sum[:], blake2ssum[:]...)

	return base64.StdEncoding.EncodeToString(cksum)
}

func (k *PrivateKeyContainer) Type() string {
	return "nacl+rsa"
}

func (k *PrivateKeyContainer) String() string {
	return fmt.Sprintf("NaCl+RSA:%s", k.Fingerprint())
}
