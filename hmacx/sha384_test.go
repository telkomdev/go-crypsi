package hmacx

import (
	"strings"
	"testing"
)

func TestHmacSha384(t *testing.T) {
	key := []byte("abc$#128djdyAgbjau&YAnmcbagryt5x")
	data := []byte("wuriyanto")

	actual, err := Sha384Hex(key, data)
	if err != nil {
		t.Error("error: hmac Sha384 returned error")
	}

	expected := "69b5b98267f760b5dc39cde790adc89358c9a59d7eac7e76c5a9e7acb9c037d0293810251de16afdf96adcbf9e512ed4"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: hmac Sha384 result is not equal to expected")
	}
}

func TestHmacSha384ShouldReturnErrorWhenKeyLessThanMin(t *testing.T) {
	invalidKey := []byte("abc")
	data := []byte("wuriyanto")

	_, err := Sha384Hex(invalidKey, data)
	if err == nil {
		t.Error("should return error when key less than min")
	}
}

func TestHmacSha384IO(t *testing.T) {
	key := []byte("abc$#128djdyAgbjau&YAnmcbagryt5x")
	data := strings.NewReader("wuriyanto")

	actual, err := Sha384IOHex(key, data)
	if err != nil {
		t.Error("error: hmac Sha384 returned error")
	}

	expected := "69b5b98267f760b5dc39cde790adc89358c9a59d7eac7e76c5a9e7acb9c037d0293810251de16afdf96adcbf9e512ed4"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: hmac Sha384 result is not equal to expected")
	}
}
