package digestx

import (
	"strings"
	"testing"
)

func TestSha384(t *testing.T) {
	data := []byte("wuriyanto")

	actual, err := Sha384Hex(data)
	if err != nil {
		t.Error("error: sha384 returned error")
	}

	expected := "2bf236501ecea775cd0eac6da0632eb236e514f29c2aff06a42819fe3b1f3d5b8aefe8c1608a8f5a4d832090902f84a1"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: sha384 result is not equal to expected")
	}
}

func TestSha384IO(t *testing.T) {
	data := strings.NewReader("wuriyanto")

	actual, err := Sha384IOHex(data)
	if err != nil {
		t.Error("error: sha384 returned error")
	}

	expected := "2bf236501ecea775cd0eac6da0632eb236e514f29c2aff06a42819fe3b1f3d5b8aefe8c1608a8f5a4d832090902f84a1"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: sha384 result is not equal to expected")
	}
}
