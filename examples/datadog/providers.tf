terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.0.0"
    }
    datadog = {
      source  = "DataDog/datadog"
      version = ">= 3.57.0" # Check for the newest version here: https://registry.terraform.io/providers/DataDog/datadog/latest
    }
  }
}

# DATADOG SETUP
module "datadog_provider_setup" {
  # Find newest version here: https://github.com/nsbno/terraform-datadog-provider-setup/releases
  source = "github.com/nsbno/terraform-datadog-provider-setup?ref=x.y.z"
}

provider "datadog" {
  api_key = module.datadog_provider_setup.api_key
  app_key = module.datadog_provider_setup.app_key

  api_url = "https://api.datadoghq.eu/"
}

provider "aws" {
  region = "eu-west-1"
}
