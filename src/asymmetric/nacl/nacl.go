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

func LoadPublicKey(data []byte, purpose int) (cryptor.PublicKey, []byte, error) {
	switch purpose {
	case cryptor.SignPurpose:
		return naclsig.LoadPublicKey(data, purpose)
	case cryptor.EncryptPurpose:
		return naclenc.LoadPublicKey(data, purpose)
	}

	return nil, nil, cryptor.ErrInvalidPurpose
}

func LoadPrivateKey(data []byte, purpose int) (cryptor.PrivateKey, []byte, error) {
	switch purpose {
	case cryptor.SignPurpose:
		return naclsig.LoadPrivateKey(data, purpose)
	case cryptor.EncryptPurpose:
		return naclenc.LoadPrivateKey(data, purpose)
	}

	return nil, nil, cryptor.ErrInvalidPurpose
}
