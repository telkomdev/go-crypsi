package digestx

import (
	"strings"
	"testing"
)

func TestSha256(t *testing.T) {
	data := []byte("wuriyanto")

	actual, err := Sha256Hex(data)
	if err != nil {
		t.Error("error: sha256 returned error")
	}

	expected := "7da544fa170151239b9886c0c905736fe3e8b07e68aefaba0633272aee47af87"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: sha256 result is not equal to expected")
	}
}

func TestSha256IO(t *testing.T) {
	data := strings.NewReader("wuriyanto")

	actual, err := Sha256IOHex(data)
	if err != nil {
		t.Error("error: sha256 returned error")
	}

	expected := "7da544fa170151239b9886c0c905736fe3e8b07e68aefaba0633272aee47af87"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: sha256 result is not equal to expected")
	}
}
