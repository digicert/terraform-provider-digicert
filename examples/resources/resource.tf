
# Define a Digicert certificate resource

resource "digicert_certificate" "cert" {
  profile_id  = "<profile_id>" # Profile ID for the certificate request
  common_name = "test.winthecustomer.com" # Common name (CN) for the certificate
  dns_names   = "san1.test.winthecustomer.com" # DNS names associated with the certificate
  tags        = "my-certificate-tag" # Optional tags to attach to the certificate
}
