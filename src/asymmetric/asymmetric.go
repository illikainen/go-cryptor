package asymmetric

import (
	"github.com/illikainen/go-cryptor/src/asymmetric/nacl"
	"github.com/illikainen/go-cryptor/src/asymmetric/rsa"
	"github.com/illikainen/go-cryptor/src/cryptor"

	log "github.com/sirupsen/logrus"
)

func GenerateKey(kind int, purpose int) (cryptor.PublicKey, cryptor.PrivateKey, error) {
	log.Tracef("generate keypair for kind=%d, purpose=%d", kind, purpose)

	switch kind {
	case cryptor.NaClAsymmetric:
		return nacl.GenerateKey(purpose)
	case cryptor.RSAAsymmetric:
		return rsa.GenerateKey(purpose)
	}

	return nil, nil, cryptor.ErrInvalidKeyType
}

func ReadPublicKey(kind int, path string, purpose int) (cryptor.PublicKey, error) {
	log.Tracef("%s: read public key for kind=%d, purpose=%d", path, kind, purpose)

	switch kind {
	case cryptor.NaClAsymmetric:
		return nacl.ReadPublicKey(path, purpose)
	case cryptor.RSAAsymmetric:
		return rsa.ReadPublicKey(path, purpose)
	}

	return nil, cryptor.ErrInvalidKeyType
}

func ReadPrivateKey(kind int, path string, purpose int) (cryptor.PrivateKey, error) {
	log.Tracef("%s: read private key for kind=%d, purpose=%d", path, kind, purpose)

	switch kind {
	case cryptor.NaClAsymmetric:
		return nacl.ReadPrivateKey(path, purpose)
	case cryptor.RSAAsymmetric:
		return rsa.ReadPrivateKey(path, purpose)
	}

	return nil, cryptor.ErrInvalidKeyType
}
