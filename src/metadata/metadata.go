package metadata

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/illikainen/go-cryptor/src/hasher"

	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Metadata struct {
	Version   uint32
	Timestamp int64
	Encrypted bool
	Keys      map[string]string
	Hashes    *hasher.Hasher
}

const MetadataSize = 1024 * 8
const Version = 0

func New(hashes *hasher.Hasher, encrypted bool, keys map[string]string) (*Metadata, error) {
	return &Metadata{
		Version:   Version,
		Timestamp: time.Now().Unix(),
		Encrypted: encrypted,
		Keys:      keys,
		Hashes:    hashes,
	}, nil
}

func Read(data []byte) (*Metadata, error) {
	md := &Metadata{}

	err := json.Unmarshal(bytes.TrimRight(data, "\x00"), md)
	if err != nil {
		return nil, err
	}

	if md.Version != Version {
		return nil, errors.Errorf("incompatible version (%d vs %d)", md.Version, Version)
	}

	return md, err
}

func (m *Metadata) Marshal() ([]byte, error) {
	tmp, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		return nil, err
	}
	tmp = append(tmp, '\n')

	if len(tmp) > MetadataSize {
		return nil, iofs.ErrInvalidSize
	}

	data := [MetadataSize]byte{}
	for i := range data {
		if i < len(tmp) {
			data[i] = tmp[i]
		} else {
			data[i] = 0
		}
	}

	return data[:], nil
}

func (m *Metadata) Compare(other *Metadata) int64 {
	if m.Hashes != other.Hashes {
		log.Debug("skipping metadata comparison")
		return 1
	}
	return m.Timestamp - other.Timestamp
}
