package symmetric

import (
	"github.com/illikainen/go-cryptor/src/cryptor"
	"github.com/illikainen/go-cryptor/src/symmetric/aesgcm"
	"github.com/illikainen/go-cryptor/src/symmetric/xchacha20poly1305"

	log "github.com/sirupsen/logrus"
)

func GenerateKey(kind int) (cryptor.SymmetricKey, error) {
	log.Tracef("generate symmetric key for kind=%d", kind)

	switch kind {
	case cryptor.AESGCMSymmetric:
		return aesgcm.GenerateKey()
	case cryptor.XCHACHA20POLY1305Symmetric:
		return xchacha20poly1305.GenerateKey()
	}

	return nil, cryptor.ErrInvalidKeyType
}

func ReadKey(kind int, data []byte) (cryptor.SymmetricKey, error) {
	log.Tracef("read symmetric key for kind=%d", kind)

	switch kind {
	case cryptor.AESGCMSymmetric:
		return aesgcm.ReadKey(data)
	case cryptor.XCHACHA20POLY1305Symmetric:
		return xchacha20poly1305.ReadKey(data)
	}

	return nil, cryptor.ErrInvalidKeyType
}
