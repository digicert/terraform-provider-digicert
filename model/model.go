package model

type ProfileResponse struct {
	Id                         string                `json:"id"`
	Name                       string                `json:"name"`
	Status                     string                `json:"status"`
	SignatureAlgorithm         string                `json:"signature_algorithm"`
	OverrideCertValidityViaApi bool                  `json:"override_cert_validity_via_api"`
	CertificateDeliveryFormat  string                `json:"certificate_delivery_format"`
	AccountId                  string                `json:"account_id"`
	EnrollmentMethod           string                `json:"enrollment_method"`
	PrivateKeyAttributes       *PrivateKeyAttributes `json:"private_key_attributes"`
	AllowedKeySizes            []string              `json:"allowed_key_sizes"`
	Template                   *Template             `json:"template"`
}

type PrivateKeyAttributes struct {
	KeySize string `json:"key_size"`
}

type Template struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type CertificateResponse struct {
	SerialNumber   string `json:"serial_number,omitempty"`
	DeliveryFormat string `json:"delivery_format,omitempty"`
	Certificate    string `json:"certificate,omitempty"`
	Status         string `json:"status,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
}

type Profile struct {
	Id string `json:"id"`
}

type Seat struct {
	SeatId string `json:"seat_id"`
}

var CertResponse struct {
	Status string `json:"status"`
}

type CertificateRequest struct {
	Profile        *Profile               `json:"profile"`
	Seat           *Seat                  `json:"seat"`
	Csr            string                 `json:"csr"`
	Attributes     map[string]interface{} `json:"attributes"`
	DeliveryFormat string                 `json:"delivery_format"`
	IncludeCaChain bool                   `json:"include_ca_chain"`
	Tags           []string               `json:"tags"`
}
