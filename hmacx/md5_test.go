package hmacx

import (
	"strings"
	"testing"
)

func TestHmacMd5(t *testing.T) {
	key := []byte("abc$#128djdyAgbjau&YAnmcbagryt5x")
	data := []byte("wuriyanto")

	actual, err := Md5Hex(key, data)
	if err != nil {
		t.Error("error: hmac md5 returned error")
	}

	expected := "d213b2e973c1a5d704255518af6d073c"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: hmac md5 result is not equal to expected")
	}
}

func TestHmacMd5ShouldReturnErrorWhenKeyLessThanMin(t *testing.T) {
	invalidKey := []byte("abc")
	data := []byte("wuriyanto")

	_, err := Md5Hex(invalidKey, data)
	if err == nil {
		t.Error("should return error when key less than min")
	}
}

func TestHmacMd5IO(t *testing.T) {
	key := []byte("abc$#128djdyAgbjau&YAnmcbagryt5x")
	data := strings.NewReader("wuriyanto")

	actual, err := Md5IOHex(key, data)
	if err != nil {
		t.Error("error: hmac md5 returned error")
	}

	expected := "d213b2e973c1a5d704255518af6d073c"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: hmac md5 result is not equal to expected")
	}
}
