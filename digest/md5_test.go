package digest

import (
	"strings"
	"testing"
)

func TestMd5(t *testing.T) {
	data := []byte("wuriyanto")

	actual, err := Md5Hex(data)
	if err != nil {
		t.Error("error: md5 returned error")
	}

	expected := "60e1bc04fa194a343b50ce67f4afcff8"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: md5 result is not equal to expected")
	}
}

func TestMd5IO(t *testing.T) {
	data := strings.NewReader("wuriyanto")

	actual, err := Md5IOHex(data)
	if err != nil {
		t.Error("error: md5 returned error")
	}

	expected := "60e1bc04fa194a343b50ce67f4afcff8"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: md5 result is not equal to expected")
	}
}
