package rsax

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestGenerateRSAKeyPairs(t *testing.T) {
	key, err := GenerateKeyPairs(KeySize4Kb)

	if err != nil {
		t.Error("error: GenerateKeyPairs() should succeed")
	}

	if key.PrivateKey == nil {
		t.Error("error: key.PrivateKey should not nil")
	}

	if key.PublicKey == nil {
		t.Error("error: key.PublicKey should not nil")
	}

	if key.GetPrivateKeyBase64Str() == "" {
		t.Error("error: key.GetPrivateKeyBase64Str() should not empty")
	}

	if key.GetPublicKeyBase64Str() == "" {
		t.Error("error: key.GetPublicKeyBase64Str() should not empty")
	}
}

func TestLoadPrivateKey(t *testing.T) {
	f, err := os.Open("./testdata/private.key")
	if err != nil {
		t.Error("error: open private.key")
	}

	defer func() { f.Close() }()

	privateKeyData, err := ioutil.ReadAll(f)
	if err != nil {
		t.Error("error: ReadAll private.key")
	}

	privateKey, err := LoadPrivateKey(privateKeyData)
	if err != nil {
		t.Error("error: LoadPrivateKey() private.key ", err)
	}

	if privateKey == nil {
		t.Error("error: privateKey should not nil")
	}
}

func TestLoadPublicKey(t *testing.T) {
	f, err := os.Open("./testdata/public.key")
	if err != nil {
		t.Error("error: open public.key")
	}

	defer func() { f.Close() }()

	publicKeyData, err := ioutil.ReadAll(f)
	if err != nil {
		t.Error("error: ReadAll public.key")
	}

	publicKey, err := LoadPublicKey(publicKeyData)
	if err != nil {
		t.Error("error: LoadPublicKey() public.key ", err)
	}

	if publicKey == nil {
		t.Error("error: publicKey should not nil")
	}
}

func TestLoadPrivateKeyAsBase64(t *testing.T) {
	f, err := os.Open("./testdata/private.key")
	if err != nil {
		t.Error("error: open private.key")
	}

	defer func() { f.Close() }()

	privateKeyData, err := ioutil.ReadAll(f)
	if err != nil {
		t.Error("error: ReadAll private.key")
	}

	privateKeyBase64, err := LoadPrivateKeyAsBase64(privateKeyData)
	if err != nil {
		t.Error("error: LoadPrivateKeyAsBase64() private.key ", err)
	}

	if privateKeyBase64 == "" {
		t.Error("error: privateKeyBase64 should not empty")
	}

	expected := "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2QUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktZd2dnU2lBZ0VBQW9JQkFRQ25jMytnUnZUVmZSMDEKVlU1NERreXRuWHVVRWQ1RkZnd0pSbnBKSEw2Mks5YTFsbGVlOXQ5T1ZKU214cVJWVkRPZGdYdDBaSjczUUp2QQpzb1BpNmpTVWlBaTVNY1NOYStMdnVLbXpzMUVBRlRLbjladjUvMkI2VWEwSllqNVd2MzB3eGFUYnk4RExmbHZjClI0ZnVFeDJQUWt6K3QwbUFRbWhScGJJY3h3QnRhK1E4a3pXZ1FMZG85ZE85N3lKb1g3aUNkZ2drMHBneXd0WGQKVWVYMjJHempLeFpRRWVuL3ZabDZ5LzVFUUVWWUpTeVdlQ3kyNXc2QjFRVmhaemFieFNQeFRiWitmcEV1eXlzRQpmeTRXdFJxUk1VYXFXb21zWGFkU3ovWFhpMU56eUZic1UrTzlYTjZwZUhrSWh2eEdYbGhNYUg5TEhWMjZCQ09WCndwZmxTaTB4QWdNQkFBRUNnZ0VBQ0N4MEcxKzdUYng0czRUQmVzeS80MjJmZlovTnFMT2x6TUlhNy95dU5uZzMKVjgvSjRTR056dVlFQjR3RXM0R1RyMm1GbkMzWk1KcC92ODAyOE5tYnpYQkNkTC9BSjJNUHhjSE96czIrODNFVgpjdXRqUExYQmdOY0J5a1o0WW9XZ1Y4UWVBdmlVSlpxNll5cytzRmxRaFJDb2IzcUU1UFRZNEx0azBWREpiWTNWCmM5TkdNSVVzd0EzY01HUHNFdnhaanFZWFNiTnVIWTltQlpHRHpzRVVlOUplWVhFekVycDY4bGYybHhBd1A4OGUKdjNOdXRJZTRhTk5Ma0VxSko1UnU2ZDVEbFVBeDYxd0R3aUIxOGgvYkNTZU02NWNLTENLd2s1ZHhFcjJRalJvcgpBaXNzT0VTZG56dDdjTVhxVlgzMFNrb3R6MFdCaWZnZjRybldiNHZ4blFLQmdRRFM5WlFpemlucGdLamFtK2ZHClNHUGhEeG5LK0pUZHFPMDlTTGZoZFdjSmhMUEZ2dXFNcFJCc0RNTXgxZGxFczQzS2IvcVpaK1BrbEt4MlNsejUKWGUzN1VtWStSQ3BHWHorY0dlNVBJVlAwbDM1d2JJL3dCNjBpd05kQ3pkUWhYQzNPN0ZqbWRHWS9CN1N4YW92cgp1SG5ZVDJoWnByMXJCQ2IvQ3ZxeE5vcWNYd0tCZ1FETE0rUnNpNDdSK0dxNUY4YlNrYjdSc0Y0VnFEanhIY0pzCmFNajJVZFpIMlNmK1pYNWtBSVltdU1qeHBBbHRveDhQcmN4ak4zTnhsY3QxYjJFdzFCU1VFZmRIU3BlVVk2MDkKUjRtVk5XcFdvVGxhV2ZhaUNDdndnRjFSVUJZcGVlV1YralJCbDFJdVZDSFYxMVNHS0k3UGczd3RoMHpxMUhYWAprZXpjRnF1Z2J3S0JnRVR0VW1KdzVBYlVMOWVGbXh3UktQa3UrdWx6Z1FoUG1ud3NsMUFHRVExdUcyTGY5empPCjhlZXIzOWNYblM2eVVBQzF4N1o1MkY4bUtKZFp3cmtEZEs5cUE5Z1NZNUdzcTFid3JnbVN4U0Nrb3Y1T3FsVHQKM1NiK3hSYWhzODdXbEcwSWtoOXlKcm92WlYyV2gzTVVTbE5mMXFOOE5HV1Q3TDNtTTNUVmNrS1hBb0dBTVFYMAo3dWNBYnRHeTFiTFJ5YzFWcnZzUXg4TE04Z2JPK0I2VGxUR0xNOHhGSk0vUm5VaXZGTHB4NkRJK0FCQmhsd1BFCkVvKzNMMGtIUys2eUVQaXBla3VYVDhERUx3MlpKdmFTVDhnU1BwSW81dzViUFI0aGs2VTBYa0NuQ0J5YmNnSnEKQndUOTA2V0NnRGV4OGFmcFJGRWhiVTUrRlExcTNMWWM0Y0FxYWNzQ2dZQkVPOUxtdWtwOGZJaFB6c3RBbEtmcApwVDViZ3E0dHh5MEo3dGNaRjI1Y2kvdlRyUkNNeWM1ZE5SMlcreTZxUmY5UmpxYTB1amN0R2swMDNjbkgyU29RCndqR3pMdW0rcVMwYVUzS05IZ3RqM0JjWlNudXdmRVJnZk1Ld2V4VVlYLzJVNGJTU28wT0ZTUG5aVnpxNUFQS2UKRFdBR0U4YU1peWlIbmpQVEMxcmFyZz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K"

	if strings.Compare(privateKeyBase64, expected) != 0 {
		t.Error("error: privateKeyBase64 should equal to expected")
	}
}

func TestLoadPublicKeyAsBase64(t *testing.T) {
	f, err := os.Open("./testdata/public.key")
	if err != nil {
		t.Error("error: open public.key")
	}

	defer func() { f.Close() }()

	publicKeyData, err := ioutil.ReadAll(f)
	if err != nil {
		t.Error("error: ReadAll public.key")
	}

	publicKeyBase64, err := LoadPublicKeyAsBase64(publicKeyData)
	if err != nil {
		t.Error("error: LoadPublicKeyAsBase64() public.key ", err)
	}

	if publicKeyBase64 == "" {
		t.Error("error: publicKeyBase64 should not empty")
	}

	expected := "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFwM04vb0ViMDFYMGROVlZPZUE1TQpyWjE3bEJIZVJSWU1DVVo2U1J5K3Rpdld0WlpYbnZiZlRsU1Vwc2FrVlZRem5ZRjdkR1NlOTBDYndMS0Q0dW8wCmxJZ0l1VEhFald2aTc3aXBzN05SQUJVeXAvV2IrZjlnZWxHdENXSStWcjk5TU1XazI4dkF5MzViM0VlSDdoTWQKajBKTS9yZEpnRUpvVWFXeUhNY0FiV3ZrUEpNMW9FQzNhUFhUdmU4aWFGKzRnbllJSk5LWU1zTFYzVkhsOXRocwo0eXNXVUJIcC83Mlplc3YrUkVCRldDVXNsbmdzdHVjT2dkVUZZV2MybThVajhVMjJmbjZSTHNzckJIOHVGclVhCmtURkdxbHFKckYyblVzLzExNHRUYzhoVzdGUGp2VnplcVhoNUNJYjhSbDVZVEdoL1N4MWR1Z1FqbGNLWDVVb3QKTVFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="

	if strings.Compare(publicKeyBase64, expected) != 0 {
		t.Error("error: publicKeyBase64 should equal to expected")
	}
}

func TestLoadPrivateKeyFromBase64(t *testing.T) {
	f, err := os.Open("./testdata/private_key_base64.txt")
	if err != nil {
		t.Error("error: open private_key_base64.txt")
	}

	defer func() { f.Close() }()

	privateKeyBase64Data, err := ioutil.ReadAll(f)
	if err != nil {
		t.Error("error: ReadAll private_key_base64.txt")
	}

	privateKey, err := LoadPrivateKeyFromBase64(privateKeyBase64Data)
	if err != nil {
		t.Error("error: LoadPrivateKeyFromBase64() private_key_base64.txt ", err)
	}

	if privateKey == nil {
		t.Error("error: privateKey should not nil")
	}

}

func TestLoadPublicKeyFromBase64(t *testing.T) {
	f, err := os.Open("./testdata/public_key_base64.txt")
	if err != nil {
		t.Error("error: open public_key_base64.txt")
	}

	defer func() { f.Close() }()

	publicKeyBase64Data, err := ioutil.ReadAll(f)
	if err != nil {
		t.Error("error: ReadAll public_key_base64.txt")
	}

	publicKey, err := LoadPublicKeyFromBase64(publicKeyBase64Data)
	if err != nil {
		t.Error("error: LoadPublicKeyFromBase64() public_key_base64.txt ", err)
	}

	if publicKey == nil {
		t.Error("error: publicKey should not nil")
	}

}
