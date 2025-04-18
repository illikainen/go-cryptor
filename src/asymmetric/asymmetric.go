package asymmetric

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/illikainen/go-cryptor/src/asymmetric/nacl"
	"github.com/illikainen/go-cryptor/src/asymmetric/naclenc"
	"github.com/illikainen/go-cryptor/src/asymmetric/naclsig"
	"github.com/illikainen/go-cryptor/src/asymmetric/rsa"
	"github.com/illikainen/go-cryptor/src/cryptor"

	"github.com/illikainen/go-utils/src/iofs"
	"github.com/illikainen/go-utils/src/stringx"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/blake2s"
)

const SignatureSize = naclsig.SignatureSize + rsa.SignatureSize

type PublicKeys struct {
	Sign    json.RawMessage
	sign    cryptor.PublicKey
	Encrypt json.RawMessage
	encrypt cryptor.PublicKey
}

type PublicKeyContainer struct {
	Type int
	NaCl PublicKeys
	RSA  PublicKeys
}

type PrivateKeys struct {
	Sign    json.RawMessage
	sign    cryptor.PrivateKey
	Encrypt json.RawMessage
	encrypt cryptor.PrivateKey
}

type PrivateKeyContainer struct {
	Type int
	NaCl PrivateKeys
	RSA  PrivateKeys
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
		Type: cryptor.PublicKeyType,
		NaCl: PublicKeys{
			sign:    naclSignPub,
			encrypt: naclEncPub,
		},
		RSA: PublicKeys{
			sign:    rsaSignPub,
			encrypt: rsaEncPub,
		},
	}
	priv := &PrivateKeyContainer{
		Type: cryptor.PrivateKeyType,
		NaCl: PrivateKeys{
			sign:    naclSignPriv,
			encrypt: naclEncPriv,
		},
		RSA: PrivateKeys{
			sign:    rsaSignPriv,
			encrypt: rsaEncPriv,
		},
	}
	return pub, priv, nil
}

func ReadPublicKey(path string) (cryptor.PublicKey, error) {
	log.Tracef("%s: read public key", path)

	data, err := iofs.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(stringx.Sanitize(data), data) {
		return nil, errors.Errorf("%s contains invalid characters", path)
	}

	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(stringx.Sanitize(decoded), decoded) {
		return nil, errors.Errorf("%s contains invalid characters", path)
	}

	key := &PublicKeyContainer{}
	err = json.Unmarshal(decoded, key)
	if err != nil {
		return nil, err
	}

	if key.Type != cryptor.PublicKeyType {
		return nil, cryptor.ErrInvalidKeyType
	}

	return key, nil
}

func ReadPublicKeyLegacy(path string) (cryptor.PublicKey, error) {
	log.Tracef("%s: read public key", path)

	buf, err := iofs.ReadFile(path)
	if err != nil {
		return nil, err
	}

	naclSignPub, rest, err := nacl.LoadPublicKeyLegacy(buf, cryptor.SignPurpose)
	if err != nil {
		return nil, err
	}

	naclEncPub, rest, err := nacl.LoadPublicKeyLegacy(rest, cryptor.EncryptPurpose)
	if err != nil {
		return nil, err
	}

	rsaSignPub, rest, err := rsa.LoadPublicKeyLegacy(rest, cryptor.SignPurpose)
	if err != nil {
		return nil, err
	}

	rsaEncPub, rest, err := rsa.LoadPublicKeyLegacy(rest, cryptor.EncryptPurpose)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.Errorf("invalid size")
	}

	pub := &PublicKeyContainer{
		Type: cryptor.PublicKeyType,
		NaCl: PublicKeys{
			sign:    naclSignPub,
			encrypt: naclEncPub,
		},
		RSA: PublicKeys{
			sign:    rsaSignPub,
			encrypt: rsaEncPub,
		},
	}
	return pub, nil
}

func ReadPrivateKey(path string) (cryptor.PrivateKey, error) {
	log.Tracef("%s: read private key", path)

	data, err := iofs.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(stringx.Sanitize(data), data) {
		return nil, errors.Errorf("%s contains invalid characters", path)
	}

	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(stringx.Sanitize(decoded), decoded) {
		return nil, errors.Errorf("%s contains invalid characters", path)
	}

	key := &PrivateKeyContainer{}
	err = json.Unmarshal(decoded, key)
	if err != nil {
		return nil, err
	}

	if key.Type != cryptor.PrivateKeyType {
		return nil, cryptor.ErrInvalidKeyType
	}

	return key, nil
}

func ReadPrivateKeyLegacy(path string) (cryptor.PrivateKey, error) {
	log.Tracef("%s: read private key", path)

	buf, err := iofs.ReadFile(path)
	if err != nil {
		return nil, err
	}

	naclSignPriv, rest, err := nacl.LoadPrivateKeyLegacy(buf, cryptor.SignPurpose)
	if err != nil {
		return nil, err
	}

	naclEncPriv, rest, err := nacl.LoadPrivateKeyLegacy(rest, cryptor.EncryptPurpose)
	if err != nil {
		return nil, err
	}

	rsaSignPriv, rest, err := rsa.LoadPrivateKeyLegacy(rest, cryptor.SignPurpose)
	if err != nil {
		return nil, err
	}

	rsaEncPriv, rest, err := rsa.LoadPrivateKeyLegacy(rest, cryptor.EncryptPurpose)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.Errorf("invalid size")
	}

	priv := &PrivateKeyContainer{
		Type: cryptor.PrivateKeyType,
		NaCl: PrivateKeys{
			sign:    naclSignPriv,
			encrypt: naclEncPriv,
		},
		RSA: PrivateKeys{
			sign:    rsaSignPriv,
			encrypt: rsaEncPriv,
		},
	}
	return priv, nil
}

func (k *PublicKeyContainer) Verify(message []byte, signature []byte) error {
	err := k.NaCl.sign.Verify(message, signature[:naclsig.SignatureSize])
	if err != nil {
		return err
	}
	log.Tracef("metadata verified with NaCl")

	err = k.RSA.sign.Verify(message, signature[naclsig.SignatureSize:])
	if err != nil {
		return err
	}
	log.Tracef("metadata verified with RSA")

	log.Tracef("metadata verified with %s", k.String())
	return nil
}

func (k *PublicKeyContainer) Encrypt(plaintext []byte) (string, error) {
	partial, err := k.NaCl.encrypt.Encrypt(plaintext)
	if err != nil {
		return "", err
	}

	ciphertext, err := k.RSA.encrypt.Encrypt([]byte(partial))
	if err != nil {
		return "", err
	}

	return ciphertext, err
}

func (k *PublicKeyContainer) MarshalJSON() ([]byte, error) {
	type alias PublicKeyContainer
	tmp := alias(*k)

	var err error
	tmp.NaCl.Sign, err = json.Marshal(k.NaCl.sign)
	if err != nil {
		return nil, err
	}

	tmp.NaCl.Encrypt, err = json.Marshal(k.NaCl.encrypt)
	if err != nil {
		return nil, err
	}

	tmp.RSA.Sign, err = json.Marshal(k.RSA.sign)
	if err != nil {
		return nil, err
	}

	tmp.RSA.Encrypt, err = json.Marshal(k.RSA.encrypt)
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(tmp)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (k *PublicKeyContainer) UnmarshalJSON(data []byte) error {
	type alias PublicKeyContainer
	tmp := &alias{}

	err := json.Unmarshal(data, tmp)
	if err != nil {
		return err
	}

	k.NaCl = PublicKeys{
		sign:    &naclsig.PublicKey{},
		encrypt: &naclenc.PublicKey{},
	}
	err = json.Unmarshal(tmp.NaCl.Sign, k.NaCl.sign)
	if err != nil {
		return err
	}
	err = json.Unmarshal(tmp.NaCl.Encrypt, k.NaCl.encrypt)
	if err != nil {
		return err
	}

	k.RSA = PublicKeys{
		sign:    &rsa.PublicKey{Purpose: cryptor.SignPurpose},
		encrypt: &rsa.PublicKey{Purpose: cryptor.EncryptPurpose},
	}
	err = json.Unmarshal(tmp.RSA.Sign, k.RSA.sign)
	if err != nil {
		return err
	}
	err = json.Unmarshal(tmp.RSA.Encrypt, k.RSA.encrypt)
	if err != nil {
		return err
	}

	k.Type = tmp.Type
	return nil
}

func (k *PublicKeyContainer) Write(path string) error {
	data, err := json.Marshal(k)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	encoded := append([]byte(base64.StdEncoding.EncodeToString(data)), '\n')
	err = os.WriteFile(path, encoded, 0600)
	if err != nil {
		return err
	}

	log.Debugf("%s: wrote %s", path, k)
	return nil
}

func (k *PublicKeyContainer) Fingerprint() string {
	fingerprints := []string{
		k.NaCl.sign.Fingerprint(),
		k.NaCl.encrypt.Fingerprint(),
		k.RSA.sign.Fingerprint(),
		k.RSA.encrypt.Fingerprint(),
	}
	sha256sum := sha256.Sum256([]byte(strings.Join(fingerprints, "")))
	blake2ssum := blake2s.Sum256([]byte(strings.Join(fingerprints, "")))
	cksum := append(sha256sum[:], blake2ssum[:]...)

	return base64.StdEncoding.EncodeToString(cksum)
}

func (k *PublicKeyContainer) String() string {
	return fmt.Sprintf("NaCl+RSA:%s", k.Fingerprint())
}

func (k *PrivateKeyContainer) Sign(message []byte) ([]byte, error) {
	naclSig, err := k.NaCl.sign.Sign(message)
	if err != nil {
		return nil, err
	}

	rsaSig, err := k.RSA.sign.Sign(message)
	if err != nil {
		return nil, err
	}

	return append(naclSig, rsaSig...), nil
}

func (k *PrivateKeyContainer) Decrypt(ciphertext string) ([]byte, error) {
	partial, err := k.RSA.encrypt.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	plaintext, err := k.NaCl.encrypt.Decrypt(string(partial))
	if err != nil {
		return nil, err
	}

	return plaintext, err
}

func (k *PrivateKeyContainer) MarshalJSON() ([]byte, error) {
	type alias PrivateKeyContainer
	tmp := alias(*k)

	var err error
	tmp.NaCl.Sign, err = json.Marshal(k.NaCl.sign)
	if err != nil {
		return nil, err
	}

	tmp.NaCl.Encrypt, err = json.Marshal(k.NaCl.encrypt)
	if err != nil {
		return nil, err
	}

	tmp.RSA.Sign, err = json.Marshal(k.RSA.sign)
	if err != nil {
		return nil, err
	}

	tmp.RSA.Encrypt, err = json.Marshal(k.RSA.encrypt)
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(tmp)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (k *PrivateKeyContainer) UnmarshalJSON(data []byte) error {
	type alias PrivateKeyContainer
	tmp := &alias{}

	err := json.Unmarshal(data, tmp)
	if err != nil {
		return err
	}

	k.NaCl = PrivateKeys{
		sign:    &naclsig.PrivateKey{},
		encrypt: &naclenc.PrivateKey{},
	}
	err = json.Unmarshal(tmp.NaCl.Sign, k.NaCl.sign)
	if err != nil {
		return err
	}
	err = json.Unmarshal(tmp.NaCl.Encrypt, k.NaCl.encrypt)
	if err != nil {
		return err
	}

	k.RSA = PrivateKeys{
		sign:    &rsa.PrivateKey{Purpose: cryptor.SignPurpose},
		encrypt: &rsa.PrivateKey{Purpose: cryptor.EncryptPurpose},
	}
	err = json.Unmarshal(tmp.RSA.Sign, k.RSA.sign)
	if err != nil {
		return err
	}
	err = json.Unmarshal(tmp.RSA.Encrypt, k.RSA.encrypt)
	if err != nil {
		return err
	}

	k.Type = tmp.Type
	return nil
}

func (k *PrivateKeyContainer) Write(path string) error {
	data, err := json.Marshal(k)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	encoded := append([]byte(base64.StdEncoding.EncodeToString(data)), '\n')
	err = os.WriteFile(path, encoded, 0600)
	if err != nil {
		return err
	}

	log.Debugf("%s: wrote %s", path, k)
	return nil
}

func (k *PrivateKeyContainer) Fingerprint() string {
	fingerprints := []string{
		k.NaCl.sign.Fingerprint(),
		k.NaCl.encrypt.Fingerprint(),
		k.RSA.sign.Fingerprint(),
		k.RSA.encrypt.Fingerprint(),
	}
	sha256sum := sha256.Sum256([]byte(strings.Join(fingerprints, "")))
	blake2ssum := blake2s.Sum256([]byte(strings.Join(fingerprints, "")))
	cksum := append(sha256sum[:], blake2ssum[:]...)

	return base64.StdEncoding.EncodeToString(cksum)
}

func (k *PrivateKeyContainer) String() string {
	return fmt.Sprintf("NaCl+RSA:%s", k.Fingerprint())
}
