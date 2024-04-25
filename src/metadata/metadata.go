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

type Config struct {
	Type      string
	Hashes    *hasher.Hasher
	Encrypted bool
	Keys      map[string]string
}

type Metadata struct {
	Type      string
	Version   uint32
	Timestamp int64
	Encrypted bool
	Keys      map[string]string
	Hashes    *hasher.Hasher
}

const MetadataSize = 1024 * 8
const Version = 0

func New(config Config) (*Metadata, error) {
	return &Metadata{
		Type:      config.Type,
		Hashes:    config.Hashes,
		Encrypted: config.Encrypted,
		Keys:      config.Keys,
		Version:   Version,
		Timestamp: time.Now().Unix(),
	}, nil
}

func Read(data []byte, typ string) (*Metadata, error) {
	md := &Metadata{}

	err := json.Unmarshal(bytes.TrimRight(data, "\x00"), md)
	if err != nil {
		return nil, err
	}

	if md.Type != typ {
		return nil, errors.Errorf("incompatible type (%s vs %s)", md.Type, typ)
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
	if m.Type != other.Type || m.Hashes != other.Hashes {
		log.Debug("skipping metadata comparison")
		return 1
	}
	return m.Timestamp - other.Timestamp
}
