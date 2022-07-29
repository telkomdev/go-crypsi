package digestx

import (
	"strings"
	"testing"
)

func TestSha1(t *testing.T) {
	data := []byte("wuriyanto")

	actual, err := Sha1Hex(data)
	if err != nil {
		t.Error("error: sha1 returned error")
	}

	expected := "afd2bd72af0c346a2ab14d50746835d3ccd1dd5f"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: sha1 result is not equal to expected")
	}
}

func TestSha1IO(t *testing.T) {
	data := strings.NewReader("wuriyanto")

	actual, err := Sha1IOHex(data)
	if err != nil {
		t.Error("error: sha1 returned error")
	}

	expected := "afd2bd72af0c346a2ab14d50746835d3ccd1dd5f"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: sha1 result is not equal to expected")
	}
}
