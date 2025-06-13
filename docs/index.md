## Provider Configuration

Configure the provider with the DigiCert ONE API base URL and an API key:

```hcl
provider "digicert" {
  url     = "<digicert_host_url>" # DigiCert API base URL
  api_key = "<digicert_api_key>"  # API key for authentication
}
```

### Provider Arguments

| Name     | Description                                                                           | Type   | Required |
|----------|--------------------------------------------------------------------------------------|--------|----------|
| url      | The URL pointing to the DigiCert ONE platform (e.g., "https://stage.one.digicert.com") | String | Yes      |
| api_key  | The api key corresponding to a user’s account for authenticating to the DigiCert ONE platform                           | String | Yes      |

## Resources

### Certificate Resource

The `digicert_certificate` resource allows you to issue and manage certificates.

#### Example with CSR

```hcl
resource "digicert_certificate" "example" {
  profile_id  = "8e201a92-4b16-412d-aa5c-bbeba3dacdef"
  common_name = "example.com"
  dns_names   = "www.example.com,api.example.com"
  csr         = "-----BEGIN CERTIFICATE REQUEST-----\nMIICjzCCAX/ZvGPbg=\n-----END CERTIFICATE REQUEST-----\n"
}
```

#### Example without CSR

```hcl
resource "digicert_certificate" "cert" {
  profile_id  = "8e201a92-4b16-412d-aa5c-bbeba3dacdef"
  common_name = "example.com"
  dns_names   = "www.example.com,api.example.com"
  tags        = "production,web-servers"
}
```

### Resource Arguments

| Name         | Description                                                   | Type           | Required |
|--------------|---------------------------------------------------------------|----------------|----------|
| profile_id   | ID of an existing DigiCert​​®​​ Trust Lifecycle Manager profile to use for certificate | String         | Yes      |
| common_name  | Common name of the certificate                                | String         | Yes      |
| dns_names    | SANs of the certificate, if any                               | Comma separated list of Strings| No       |
| csr          | Certificate Signing Request (CSR) in PEM format               | String         | No       |
| tags         | Tags to attach to the certificate                             | Comma separated list of Strings| No       |

After enrollment, the `digicert_certificate` resource will expose:

| Name          | Description                                      |
|---------------|--------------------------------------------------|
| id            | Unique identifier for the certificate            |
| serial_number | Serial number of the issued certificate          |
| status        | Current status of the certificate                |
| thumbprint    | SHA-1 thumbprint of the certificate              |
| valid_from    | Certificate validity start date                  |
| valid_to      | Certificate validity end date                    |
| certificate   | Issued certificate in PEM format                 |
| chain_pem     | Certificate chain in PEM format                  |
| request_id    | Request ID for the certificate issuance          |

## Certificate Outputs

Certificate outputs allow you to retrieve and use certificate details in your infrastructure or for verification purposes. When you define outputs, Terraform will display or make available specific certificate information after creation.

### Output Example

```hcl
output "certificate_pem" {
  value     = digicert_certificate.cert.certificate
  sensitive = true
}

output "certificate_serial" {
  value = digicert_certificate.cert.serial_number
}
```
## Certificate Management

### Creating Certificates

1. Verify your configuration:
    To check if your configuration is correct, run:
    ```
    terraform plan
    ```
    This command:

    Validates the syntax and provider settings.

    Displays the changes Terraform will make without applying them.

    If there are no errors, proceed to the next step.

2. Apply the configuration:
    To create the certificates, execute:
    ```
    terraform apply
    ```
    Terraform will prompt for confirmation. Type yes and press Enter to proceed.

    Upon successful execution, Terraform will:

    Send a request to the DigiCert​​®​​ Trust Lifecycle Manager API.

    Issue the requested certificates.

    Store the certificate details in the Terraform state.
3. View the Applied Configuration:
    To review the applied Terraform state, run:
    ```
    terraform show
    ```

## Revoking Certificates

There are multiple ways to revoke certificates in Terraform:

### Method 1: Remove Resource from Configuration

1. Remove the specific certificate resource from your Terraform configuration file.
2. Run Terraform plan and apply:
   ```
   terraform plan
   terraform apply
   ```
   This will automatically detect the removed resource and revoke the corresponding certificate.

### Method 2: Targeted Destruction

Revoke a specific certificate by targeting its resource:

```
terraform destroy -target=digicert_certificate.example
```

### Method 3: Complete Destruction

Revoke all managed certificates:

```
terraform destroy
```
(Be cautious, as this will remove the issued certificates.)

### Important Notes on Revocation

- Removing a certificate resource from the configuration or using `destroy` will trigger certificate revocation.
- The certificate will be removed from both the DigiCert ONE platform and the Terraform state file.
- Always use `terraform plan` before `apply` or `destroy` to preview changes.

## Security Best Practices

### Protecting Terraform State Files

The Terraform state file contains critical infrastructure information, including sensitive data. 

Recommendations:
- **Secure Storage**: Use remote backends with encryption and access controls:
  - HashiCorp's Terraform Cloud
  - AWS S3 with proper IAM policies
  - Google Cloud Storage with appropriate permissions
- **Access Control**: 
  - Restrict state file access to only necessary individuals or systems
  - Implement least privilege access principles

For comprehensive guidelines, refer to [HashiCorp's Sensitive Data in State documentation](https://www.terraform.io/language/state/sensitive-data).

## Troubleshooting
- Error: API request failed (401 Unauthorized)

  - Ensure the DigiCert ONE API key is valid and has required access.

- Error: Validation failed due to unknown attributes

  - Check the DigiCert​​®​​ Trust Lifecycle Manager API documentation for the correct certificate attributes.

- Error: Certificate issuance failed (400 Bad Request)

  - Ensure all required fields are correctly defined in main.tf.

For more details, refer to the [DigiCert​​®​​ Trust Lifecycle Manager API documentation](https://stage.one.digicert.com/mpki/docs/swagger-ui/index.html#/Inventory) or enable Terraform debugging:
  ```
  TF_LOG=DEBUG terraform apply
  ```

## Contributing

DigiCert Terraform Provider is open-source, meaning you can freely download, use, modify, and distribute it according to the terms of our license. However, this is not an open contribution project.
To maintain code quality, security standards, and alignment with our internal development roadmap, we do not accept direct code contributions from external contributors. Our internal development team is solely responsible for all code changes and enhancements.

## Contact Us

If you have any questions, suggestions, or issues regarding this provider, you can contact us at terraform-provider-support@digicert.com.

## License

Copyright © 2025 DigiCert, Inc. All rights reserved.

This project is licensed under the MIT. See the [LICENSE](./LICENSE) file for more information.
