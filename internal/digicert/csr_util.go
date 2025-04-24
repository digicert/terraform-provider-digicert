package digicert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/digicert/digicert-terraform-provider/model"
)

const (
	keyTypeSeparator = "_WITH_"
	separatorLength  = len(keyTypeSeparator)

	KeyTypeECDSA = "ECDSA"
	KeyTypeRSA   = "RSA"

	EllipticCurveP256 = 256
	EllipticCurveP384 = 384
	EllipticCurveP521 = 521
)

func generateCSR(data *issuanceData) (string, []byte, error) {
	var err error
	profile := data.profile

	keyType, err := parseKeyType(profile.SignatureAlgorithm)
	if err != nil {
		return "", nil, err
	}

	keySize, err := parseKeySize(profile.PrivateKeyAttributes)
	if err != nil {
		return "", nil, err
	}

	privateKey, err := generatePrivateKey(keyType, keySize)
	if err != nil {
		return "", nil, err
	}

	subject := pkix.Name{
		CommonName: data.cn,
	}
	rawSubject := subject.ToRDNSequence()
	asn1Subject, err := asn1.Marshal(rawSubject)
	if err != nil {
		return "", nil, err
	}

	certificateRequest := x509.CertificateRequest{
		RawSubject: asn1Subject,
		DNSNames:   data.dnsNames,
	}
	err = setSignatureAlgorithm(&certificateRequest, keyType, profile.SignatureAlgorithm)
	if err != nil {
		return "", nil, err
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequest, privateKey)
	if err != nil {
		return "", nil, err
	}

	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	privateKeyBytes, err := getEncodedPrivateKey(privateKey)
	if err != nil {
		return "", nil, err
	}

	return string(csr), privateKeyBytes, nil
}

// Generates private key based on the key type and size
func generatePrivateKey(keyType string, keySize int) (crypto.Signer, error) {

	var privateKey crypto.Signer
	var err error

	switch keyType {
	case KeyTypeECDSA:
		privateKey, err = generateECDSAPrivateKey(keySize)
	case KeyTypeRSA:
		privateKey, err = generateRSAPrivateKey(keySize)
	default:
		return nil, fmt.Errorf("unable to generate CSR. keyType %s is not supported", keyType)
	}

	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Generates ECDSA private key using the specified key curve
func generateECDSAPrivateKey(keySize int) (*ecdsa.PrivateKey, error) {

	var c elliptic.Curve

	switch keySize {
	case EllipticCurveP256:
		c = elliptic.P256()
	case EllipticCurveP384:
		c = elliptic.P384()
	case EllipticCurveP521:
		c = elliptic.P521()
	default:
		return nil, fmt.Errorf("unable to generate ECDSA key. keySize %d is not supported", keySize)
	}

	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Generates RSA private key using the specified key size
func generateRSAPrivateKey(keySize int) (*rsa.PrivateKey, error) {

	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Fetch key type from the profile
func parseKeyType(signAlgorithm string) (string, error) {

	index := strings.Index(signAlgorithm, keyTypeSeparator)
	if index != -1 {
		return signAlgorithm[index+separatorLength:], nil
	}

	return "", fmt.Errorf("unable to fetch keyType from profile")
}

// Fetch key size from the profile
func parseKeySize(privateKeyAttributes *model.PrivateKeyAttributes) (int, error) {

	if privateKeyAttributes == nil || len(privateKeyAttributes.KeySize) == 0 {
		return -1, fmt.Errorf("unable to fetch keySize from profile")
	}

	keySizeStr := strings.Replace(privateKeyAttributes.KeySize, "P-", "", -1)
	keySize, err := strconv.Atoi(keySizeStr)
	if err != nil {
		return -1, fmt.Errorf("unable to fetch keySize from profile")
	}

	return keySize, nil
}

// Fetch signature algorithm from the profile
func parseSignatureHash(signAlgorithm string) (string, error) {

	index := strings.Index(signAlgorithm, keyTypeSeparator)
	if index != -1 {
		return signAlgorithm[:index], nil
	}

	return "", fmt.Errorf("unable to fetch signatureAlgorithm from profile")
}

// Sets the signature algorithm in CSR
func setSignatureAlgorithm(certificateRequest *x509.CertificateRequest, keyType, signAlgorithm string) error {

	signatureHash, err := parseSignatureHash(signAlgorithm)
	if err != nil {
		return err
	}

	switch signatureHash {
	case "SHA256":
		switch keyType {
		case KeyTypeECDSA:
			certificateRequest.SignatureAlgorithm = x509.ECDSAWithSHA256
		case KeyTypeRSA:
			certificateRequest.SignatureAlgorithm = x509.SHA256WithRSA
		}
	case "SHA384":
		switch keyType {
		case KeyTypeECDSA:
			certificateRequest.SignatureAlgorithm = x509.ECDSAWithSHA384
		case KeyTypeRSA:
			certificateRequest.SignatureAlgorithm = x509.SHA384WithRSA
		}
	case "SHA512":
		switch keyType {
		case KeyTypeECDSA:
			certificateRequest.SignatureAlgorithm = x509.ECDSAWithSHA512
		case KeyTypeRSA:
			certificateRequest.SignatureAlgorithm = x509.SHA512WithRSA
		}
	default:
		return fmt.Errorf("unable to generate CSR. hash function %s is not supported", signatureHash)
	}

	return nil
}

// Encodes the private key in PEM format.
func getEncodedPrivateKey(privateKey crypto.Signer) ([]byte, error) {

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}), nil
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		}), nil
	default:
		return nil, fmt.Errorf("unable to encode private key. %v is not supported", key)
	}
}

func generateSeatId(cn string) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 6)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return cn
		}
		b[i] = letters[num.Int64()]
	}
	return cn + "_" + string(b)
}
