# Define the required providers for Terraform

terraform {
  required_providers {
    digicert = {
      source = "digicert/digicert" # Specify the provider source for Digicert
    }
  }
}

# Configure the Digicert provider with the API URL and API key

provider "digicert" {
  url    = "<digicert_host_url>" # Digicert API base URL
  api_key = "<digicert_api_key>" # API key for authentication
}