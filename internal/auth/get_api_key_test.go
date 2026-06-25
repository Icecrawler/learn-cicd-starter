package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key-123")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if key != "my-secret-key-123" {
		t.Errorf("expected key %q, got %q", "my-secret-key-123", key)
	}
}

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got: %v", err)
	}
}

func TestGetAPIKey_MalformedHeader_WrongPrefix(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer my-secret-key-123")

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if err.Error() != "malformed authorization header" {
		t.Errorf("expected malformed authorization header error, got: %v", err)
	}
}

func TestGetAPIKey_MalformedHeader_MissingKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey")

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if err.Error() != "malformed authorization header" {
		t.Errorf("expected malformed authorization header error, got: %v", err)
	}
}

func TestGetAPIKey_EmptyHeaderValue(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "")

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got: %v", err)
	}
}
