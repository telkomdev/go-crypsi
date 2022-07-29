package digestx

import (
	"strings"
	"testing"
)

func TestSha512(t *testing.T) {
	data := []byte("wuriyanto")

	actual, err := Sha512Hex(data)
	if err != nil {
		t.Error("error: sha512 returned error")
	}

	expected := "5adf884c57a5dc4f353bb08a138953e98320c35843ec86dd42e866e9111f39f502dd250a31f421c9eae8b0593540c30b4ecba6f7f5356632aeea308ee5a5a206"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: sha512 result is not equal to expected")
	}
}

func TestSha512MultipleInput(t *testing.T) {
	data1 := []byte("wuriyanto")
	data2 := []byte("musobar")

	datas := [][]byte{data1, data2}

	actual, err := Sha512Hex(datas...)
	if err != nil {
		t.Error("error: sha512 returned error")
	}

	expected := "83bd0d5214a0eb7a7d61554df9edeb0fec193e43680654984e1b7c100efedab72c047fd2f137bdd650e39bd9bfa872af7510b2a0101e2d7315cc0f900b8e44ba"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: sha512 result is not equal to expected")
	}
}

func TestSha512IO(t *testing.T) {
	data := strings.NewReader("wuriyanto")

	actual, err := Sha512IOHex(data)
	if err != nil {
		t.Error("error: sha512 returned error")
	}

	expected := "5adf884c57a5dc4f353bb08a138953e98320c35843ec86dd42e866e9111f39f502dd250a31f421c9eae8b0593540c30b4ecba6f7f5356632aeea308ee5a5a206"

	if strings.Compare(actual, expected) != 0 {
		t.Error("error: sha512 result is not equal to expected")
	}
}
