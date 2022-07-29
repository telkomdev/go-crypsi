package hmacx

import (
	"strings"
	"testing"
)

func TestHmacSha256(t *testing.T) {
	key := []byte("abc$#128djdyAgbjau&YAnmcbagryt5x")
	data := []byte("wuriyanto")

	actual, err := Sha256Hex(key, data)
	if err != nil {
		t.Error("error: hmac Sha256 returned error")
	}

	expected := "9f46bcc1bdc24ff2d4b6f811c1dd7e053089e515b0525c2b2a7ff25c28eb4240"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: hmac Sha256 result is not equal to expected")
	}
}

func TestHmacSha256ShouldReturnErrorWhenKeyLessThanMin(t *testing.T) {
	invalidKey := []byte("abc")
	data := []byte("wuriyanto")

	_, err := Sha256Hex(invalidKey, data)
	if err == nil {
		t.Error("should return error when key less than min")
	}
}

func TestHmacSha256IO(t *testing.T) {
	key := []byte("abc$#128djdyAgbjau&YAnmcbagryt5x")
	data := strings.NewReader("wuriyanto")

	actual, err := Sha256IOHex(key, data)
	if err != nil {
		t.Error("error: hmac Sha256 returned error")
	}

	expected := "9f46bcc1bdc24ff2d4b6f811c1dd7e053089e515b0525c2b2a7ff25c28eb4240"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: hmac Sha256 result is not equal to expected")
	}
}
