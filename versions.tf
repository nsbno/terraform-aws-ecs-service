terraform {
  required_version = ">= 1.4.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.15.0"
    }
    external = {
      source  = "hashicorp/external"
      version = ">= 2.3.0"
    }
    awscc = {
      source  = "hashicorp/awscc"
      version = ">= 1.0.0"
    }
  }
}
