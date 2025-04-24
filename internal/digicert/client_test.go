package digicert

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/digicert/digicert-terraform-provider/model"
	"github.com/stretchr/testify/assert"
)

func TestClientAuthorize_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/mpki/api/v1/hello", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("accept"))
		assert.Equal(t, "test-api-key", r.Header.Get("X-API-Key"))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from DigiCert ONE - Trust Lifecycle Manager REST API!"))
	}))
	defer server.Close()

	client := digicertClient{
		Url:        server.URL,
		ApiKey:     "test-api-key",
		HTTPClient: server.Client(),
	}

	err := client.Authorize(server.URL, "test-api-key")
	assert.NoError(t, err, "Expected authorize to succeed")
}

func TestClientAuthorize_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer server.Close()

	client := digicertClient{
		Url:        server.URL,
		ApiKey:     "test-api-key",
		HTTPClient: server.Client(),
	}

	err := client.Authorize(server.URL, "test-api-key")
	assert.Error(t, err, "Expected authorize to fail with an error")
	assert.Contains(t, err.Error(), "API request failed with status code", "Error message should mention status code")
}

func TestRevokeCertificate_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		expectedPath := fmt.Sprintf("/mpki/api/v1/certificate/%s/revoke", "123456789")
		assert.Equal(t, expectedPath, r.URL.Path)

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := digicertClient{
		Url:        server.URL,
		ApiKey:     "test-api-key",
		HTTPClient: server.Client(),
	}

	err := client.RevokeCertificate("123456789")
	assert.NoError(t, err, "Expected sendDeleteCertificateRequest to succeed")
}

func TestRevokeCertificate_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "bad request"}`))
	}))
	defer server.Close()

	client := digicertClient{
		Url:        server.URL,
		ApiKey:     "test-api-key",
		HTTPClient: server.Client(),
	}

	err := client.RevokeCertificate("123456789")
	assert.Error(t, err, "Expected sendDeleteCertificateRequest to fail")
	assert.Contains(t, err.Error(), "API request failed with status code", "Error message should indicate the failure status code")
}
func TestClientIssueCertificate_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/mpki/api/v1/certificate", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "test-api-key", r.Header.Get("X-API-Key"))

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id": "123456789", "status": "issued"}`))
	}))
	defer server.Close()

	client := digicertClient{
		Url:        server.URL,
		ApiKey:     "test-api-key",
		HTTPClient: server.Client(),
	}

	request := &model.CertificateRequest{
		// Set the request fields here
	}

	response, err := client.IssueCertificate(request)
	assert.NoError(t, err, "Expected IssueCertificate to succeed")
	assert.NotNil(t, response, "Expected non-nil response")

	// Add assertions for the response fields
	assert.Equal(t, "issued", response.Status)
}

func TestClientIssueCertificate_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal server error"}`))
	}))
	defer server.Close()

	client := digicertClient{
		Url:        server.URL,
		ApiKey:     "test-api-key",
		HTTPClient: server.Client(),
	}

	request := &model.CertificateRequest{
		// Set the request fields here
	}

	response, err := client.IssueCertificate(request)
	assert.Error(t, err, "Expected IssueCertificate to fail")
	assert.Nil(t, response, "Expected nil response")
	assert.Contains(t, err.Error(), "certificate issuance failed with status code", "Error message should mention status code")
}
func TestClientGetProfile_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		expectedPath := fmt.Sprintf("/mpki/api/v2/profile/%s", "profile-id")
		assert.Equal(t, expectedPath, r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "test-api-key", r.Header.Get("X-API-Key"))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": "profile-id", "name": "Test Profile"}`))
	}))
	defer server.Close()

	client := digicertClient{
		Url:        server.URL,
		ApiKey:     "test-api-key",
		HTTPClient: server.Client(),
	}

	response, err := client.GetProfile("profile-id")
	assert.NoError(t, err, "Expected GetProfile to succeed")
	assert.NotNil(t, response, "Expected non-nil response")

	// Add assertions for the response fields
	assert.Equal(t, "Test Profile", response.Name)
}

func TestClientGetProfile_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal server error"}`))
	}))
	defer server.Close()

	client := digicertClient{
		Url:        server.URL,
		ApiKey:     "test-api-key",
		HTTPClient: server.Client(),
	}

	response, err := client.GetProfile("profile-id")
	assert.Error(t, err, "Expected GetProfile to fail")
	assert.Nil(t, response, "Expected nil response")
	assert.Contains(t, err.Error(), "get profile details failed with status code", "Error message should mention status code")
}
func TestClientPickupCertificate_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		expectedPath := fmt.Sprintf("/mpki/api/v1/certificate-pickup/%s", "request-id")
		assert.Equal(t, expectedPath, r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "test-api-key", r.Header.Get("X-API-Key"))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": "certificate-id", "status": "PENDING"}`))
	}))
	defer server.Close()

	client := digicertClient{
		Url:        server.URL,
		ApiKey:     "test-api-key",
		HTTPClient: server.Client(),
	}

	response, pending, err := client.PickupCertificate("request-id", "profile-id")
	assert.NoError(t, err, "Expected PickupCertificate to succeed")
	assert.NotNil(t, response, "Expected non-nil response")
	assert.True(t, pending, "Expected pending to be true")

	// Add assertions for the response fields
	assert.Equal(t, "PENDING", response.Status)
}

func TestClientPickupCertificate_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal server error"}`))
	}))
	defer server.Close()

	client := digicertClient{
		Url:        server.URL,
		ApiKey:     "test-api-key",
		HTTPClient: server.Client(),
	}

	response, pending, err := client.PickupCertificate("request-id", "profile-id")
	assert.Error(t, err, "Expected PickupCertificate to fail")
	assert.Nil(t, response, "Expected nil response")
	assert.False(t, pending, "Expected pending to be false")
	assert.Contains(t, err.Error(), "certificate pickup failed with status code", "Error message should mention status code")
}
