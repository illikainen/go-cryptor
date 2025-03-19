package nacl

import (
	"github.com/illikainen/go-cryptor/src/asymmetric/naclenc"
	"github.com/illikainen/go-cryptor/src/asymmetric/naclsig"
	"github.com/illikainen/go-cryptor/src/cryptor"
)

func GenerateKey(purpose int) (cryptor.PublicKey, cryptor.PrivateKey, error) {
	switch purpose {
	case cryptor.SignPurpose:
		return naclsig.GenerateKey(purpose)
	case cryptor.EncryptPurpose:
		return naclenc.GenerateKey(purpose)
	}

	return nil, nil, cryptor.ErrInvalidPurpose
}

func LoadPublicKeyLegacy(data []byte, purpose int) (cryptor.PublicKey, []byte, error) {
	switch purpose {
	case cryptor.SignPurpose:
		return naclsig.LoadPublicKeyLegacy(data, purpose)
	case cryptor.EncryptPurpose:
		return naclenc.LoadPublicKeyLegacy(data, purpose)
	}

	return nil, nil, cryptor.ErrInvalidPurpose
}

func LoadPrivateKeyLegacy(data []byte, purpose int) (cryptor.PrivateKey, []byte, error) {
	switch purpose {
	case cryptor.SignPurpose:
		return naclsig.LoadPrivateKeyLegacy(data, purpose)
	case cryptor.EncryptPurpose:
		return naclenc.LoadPrivateKeyLegacy(data, purpose)
	}

	return nil, nil, cryptor.ErrInvalidPurpose
}
