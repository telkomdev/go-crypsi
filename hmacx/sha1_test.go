package hmacx

import (
	"strings"
	"testing"
)

func TestHmacSha1(t *testing.T) {
	key := []byte("abc$#128djdyAgbjau&YAnmcbagryt5x")
	data := []byte("wuriyanto")

	actual, err := Sha1Hex(key, data)
	if err != nil {
		t.Error("error: hmac Sha1 returned error")
	}

	expected := "69fa82ae1f1398e6e570a4780df908adad3998df"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: hmac Sha1 result is not equal to expected")
	}
}

func TestHmacSha1ShouldReturnErrorWhenKeyLessThanMin(t *testing.T) {
	invalidKey := []byte("abc")
	data := []byte("wuriyanto")

	_, err := Sha1Hex(invalidKey, data)
	if err == nil {
		t.Error("should return error when key less than min")
	}
}

func TestHmacSha1IO(t *testing.T) {
	key := []byte("abc$#128djdyAgbjau&YAnmcbagryt5x")
	data := strings.NewReader("wuriyanto")

	actual, err := Sha1IOHex(key, data)
	if err != nil {
		t.Error("error: hmac Sha1 returned error")
	}

	expected := "69fa82ae1f1398e6e570a4780df908adad3998df"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: hmac Sha1 result is not equal to expected")
	}
}
