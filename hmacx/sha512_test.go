package hmacx

import (
	"strings"
	"testing"
)

func TestHmacSha512(t *testing.T) {
	key := []byte("abc$#128djdyAgbjau&YAnmcbagryt5x")
	data := []byte("wuriyanto")

	actual, err := Sha512Hex(key, data)
	if err != nil {
		t.Error("error: hmac Sha512 returned error")
	}

	expected := "0084af8c8d831581b30f3ef2a250355bb04f2b2ca632d656ab8dce2b34692e5238ed19f7638070a115196dd928dfff3717dddf9d072ae9c26716c8faa11a25f8"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: hmac Sha512 result is not equal to expected")
	}
}

func TestHmacSha512ShouldReturnErrorWhenKeyLessThanMin(t *testing.T) {
	invalidKey := []byte("abc")
	data := []byte("wuriyanto")

	_, err := Sha512Hex(invalidKey, data)
	if err == nil {
		t.Error("should return error when key less than min")
	}
}

func TestHmacSha512IO(t *testing.T) {
	key := []byte("abc$#128djdyAgbjau&YAnmcbagryt5x")
	data := strings.NewReader("wuriyanto")

	actual, err := Sha512IOHex(key, data)
	if err != nil {
		t.Error("error: hmac Sha512 returned error")
	}

	expected := "0084af8c8d831581b30f3ef2a250355bb04f2b2ca632d656ab8dce2b34692e5238ed19f7638070a115196dd928dfff3717dddf9d072ae9c26716c8faa11a25f8"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: hmac Sha512 result is not equal to expected")
	}
}
