package hmacx

import (
	"errors"
	"hash"
	"io"
)

const (
	minHmacKey = 32
)

var (
	errorHmacKeyLenLessThanMin = errors.New("hmac key length not valid")
)

func checkKeyLen(key []byte) error {
	if len(key) < minHmacKey {
		return errorHmacKeyLenLessThanMin
	}

	return nil
}

func mac(h hash.Hash, datas ...[]byte) ([]byte, error) {
	for _, data := range datas {
		_, err := h.Write(data)
		if err != nil {
			return nil, err
		}
	}

	return h.Sum(nil), nil
}

func macIO(h hash.Hash, r io.Reader) ([]byte, error) {
	_, err := io.Copy(h, r)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
