package digicert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/digicert/digicert-terraform-provider/model"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	keyCompromise        = "key_compromise"
	expectedAuthResponse = "Hello from DigiCert ONE - Trust Lifecycle Manager REST API!"
	statusIssued         = "ISSUED"
	statusPending        = "PENDING"
	revokedCertError     = "Certificate already has been revoked"
)

type Client interface {
	Authorize(hostUrl, apiKey string) error
	GetProfile(profileId string) (*model.ProfileResponse, error)
	PickupCertificate(requestId, profileId string) (*model.CertificateResponse, bool, error)
	RevokeCertificate(serialNumber string) error
	ReadCertificate(serialNumber string) (string, error)
	IssueCertificate(certificateRequest *model.CertificateRequest) (*model.CertificateResponse, error)
}

type digicertClient struct {
	Url        string
	HTTPClient *http.Client
	ApiKey     string
}

func NewClient(url, apiKey string) (Client, error) {

	c := &digicertClient{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		Url:        url,
		ApiKey:     apiKey,
	}

	// If username or password not provided, return empty client
	if url == "" || apiKey == "" {
		return c, nil
	}

	err := c.Authorize(url, apiKey)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *digicertClient) Authorize(hostUrl, apiKey string) error {

	path := "/mpki/api/v1/hello"
	fullUrl := fmt.Sprintf("%s%s", hostUrl, path)
	req, err := http.NewRequest("GET", fullUrl, nil)
	if err != nil {
		return err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status code %d", resp.StatusCode)
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if string(responseBody) != expectedAuthResponse {
		return fmt.Errorf("API request failed with unexpected response: %s", string(responseBody))
	}

	return nil
}

func (c *digicertClient) GetProfile(profileId string) (*model.ProfileResponse, error) {

	req, err := http.NewRequest("GET", c.Url+"/mpki/api/v2/profile/"+profileId, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-API-Key", c.ApiKey)
	req.Header.Add("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Parse error response
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get profile details failed with status code %d and error "+string(body), resp.StatusCode)
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse response
	var profileResponse model.ProfileResponse
	err = json.Unmarshal(responseBody, &profileResponse)
	if err != nil {
		return nil, fmt.Errorf("unable to parse profile response : %v", err)
	}

	return &profileResponse, nil
}

func (c *digicertClient) PickupCertificate(requestID, profileID string) (*model.CertificateResponse, bool, error) {
	url := fmt.Sprintf("%s/mpki/api/v1/certificate-pickup/%s", c.Url, requestID)

	requestBody := map[string]interface{}{
		"profile": map[string]string{
			"id": profileID,
		},
	}

	requestData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, false, fmt.Errorf("failed to marshal request body: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestData))
	if err != nil {
		return nil, false, err
	}

	req.Header.Set("X-API-Key", c.ApiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("certificate pickup failed with status code %d: %s", resp.StatusCode, string(body))
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}

	var certResponse model.CertificateResponse
	err = json.Unmarshal(responseBody, &certResponse)
	if err != nil {
		return nil, false, fmt.Errorf("unable to parse certificate response: %v", err)
	}

	if certResponse.Status == "PENDING" {
		return &certResponse, true, nil
	}

	return &certResponse, false, nil
}

func buildIssuanceRequest(issuanceData *issuanceData) *model.CertificateRequest {

	attributes := map[string]interface{}{
		"subject": map[string]interface{}{
			"common_name": issuanceData.cn,
		},
	}

	if len(issuanceData.dnsNames) > 0 {
		attributes["extensions"] = map[string]interface{}{
			"san": map[string]interface{}{
				"dns_names": issuanceData.dnsNames,
			},
		}
	}

	return &model.CertificateRequest{
		Profile: &model.Profile{
			Id: issuanceData.profile.Id,
		},
		Seat: &model.Seat{
			SeatId: generateSeatId(issuanceData.cn),
		},
		Csr:            issuanceData.csr,
		Attributes:     attributes,
		DeliveryFormat: issuanceData.profile.CertificateDeliveryFormat,
		IncludeCaChain: true,
		Tags:           issuanceData.tags,
	}
}

func (c *digicertClient) IssueCertificate(request *model.CertificateRequest) (*model.CertificateResponse, error) {

	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("error building issuance request : %v", err)
	}

	req, err := http.NewRequest("POST", c.Url+"/mpki/api/v1/certificate", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-API-Key", c.ApiKey)
	req.Header.Add("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		// Parse error response
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("certificate issuance failed with status code %d and error "+string(body), resp.StatusCode)
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse response
	var certificateResponse model.CertificateResponse
	err = json.Unmarshal(responseBody, &certificateResponse)
	if err != nil {
		return nil, fmt.Errorf("unable to parse issuance response : %v", err)
	}

	return &certificateResponse, nil
}

func (c *digicertClient) RevokeCertificate(serialNumber string) error {
	path := fmt.Sprintf("/mpki/api/v1/certificate/%s/revoke", serialNumber)
	fullUrl := fmt.Sprintf("%s%s", c.Url, path)

	// Request body (mandatory)
	payload := map[string]string{
		"revocation_reason": keyCompromise,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", fullUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}

	req.Header.Set("X-API-Key", c.ApiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("unable to read response body: %v", readErr)
		}

		var errorResponse struct {
			Errors []struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
		}

		if jsonErr := json.Unmarshal(bodyBytes, &errorResponse); jsonErr != nil {
			return fmt.Errorf("unable to parse error response: %v", jsonErr)
		}

		ctx := context.Background()
		for _, e := range errorResponse.Errors {
			if e.Message == CertificateRevokedError {
				tflog.Warn(ctx, CertificateRevokedError, map[string]interface{}{"serial_number": serialNumber})
				return fmt.Errorf(CertificateRevokedError)
			}
		}

		tflog.Warn(ctx, "Failed to revoke certificate", map[string]interface{}{"serial_number": serialNumber, "errors": errorResponse.Errors})
		return fmt.Errorf("API request failed with status code %d", resp.StatusCode)
	}

	return nil
}

func (c *digicertClient) ReadCertificate(serialNumber string) (string, error) {
	path := fmt.Sprintf("/mpki/api/v1/certificate/%s", serialNumber)
	fullUrl := fmt.Sprintf("%s%s", c.Url, path)

	req, err := http.NewRequest("GET", fullUrl, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("X-API-Key", c.ApiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return "", fmt.Errorf("unable to read response body: %v", readErr)
	}

	if jsonErr := json.Unmarshal(bodyBytes, &model.CertResponse); jsonErr != nil {
		return "", fmt.Errorf("unable to parse error response: %v", jsonErr)
	}

	return model.CertResponse.Status, nil
}
