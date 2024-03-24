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

func ReadPublicKey(path string, purpose int) (cryptor.PublicKey, error) {
	switch purpose {
	case cryptor.SignPurpose:
		return naclsig.ReadPublicKey(path, purpose)
	case cryptor.EncryptPurpose:
		return naclenc.ReadPublicKey(path, purpose)
	}

	return nil, cryptor.ErrInvalidPurpose
}

func ReadPrivateKey(path string, purpose int) (cryptor.PrivateKey, error) {
	switch purpose {
	case cryptor.SignPurpose:
		return naclsig.ReadPrivateKey(path, purpose)
	case cryptor.EncryptPurpose:
		return naclenc.ReadPrivateKey(path, purpose)
	}

	return nil, cryptor.ErrInvalidPurpose
}
