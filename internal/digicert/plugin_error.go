package digicert

const (
	MissingAPIKeyError       = "Missing api key"
	MissingAPIURLError       = "Missing url"
	MissingTags              = "Missing tags"
	MissingDNSName           = "Missing dns name"
	MissingRequestIDError    = "Missing request id"
	InvalidTagsError         = "Invalid tags"
	MissingCommonNameError   = "Missing common name"
	MissingProfileIDError    = "Missing profile id"
	ClientConfigureError     = "Unable to create Digicert client"
	ProfileFetchError        = "Error fetching profile"
	CSRGenerationError       = "Error generating csr"
	CreateCertificateError   = "Error creating certificate"
	CertificateRevokedError  = "Certificate already has been revoked"
	CertificateFetchError    = "Error getting certificate details"
	CertificatePendingError  = "Certificate is still pending"
	CertificateDeleteError   = "Error deleting certificate"
	MissingSerialNumberError = "Missing serial number"
)
