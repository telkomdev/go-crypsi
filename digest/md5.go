package digest

import (
	"crypto/md5"
	"encoding/hex"
	"io"
)

// Md5 returns the MD5 checksum of the data
func Md5(datas ...[]byte) ([]byte, error) {
	return digest(md5.New(), datas...)
}

// Md5Hex returns the MD5 checksum of the data with HEX format
func Md5Hex(datas ...[]byte) (string, error) {
	b, err := digest(md5.New(), datas...)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

// Md5IO returns the MD5 checksum of the io.Reader
func Md5IO(r io.Reader) ([]byte, error) {
	return digestIO(md5.New(), r)
}

// Md5IOHex returns the MD5 checksum of the io.Reader with HEX format
func Md5IOHex(r io.Reader) (string, error) {
	b, err := digestIO(md5.New(), r)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
