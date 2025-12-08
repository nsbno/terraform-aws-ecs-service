terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.15.0, <7.0.0"
    }
    datadog = {
      source  = "DataDog/datadog"
      version = ">= 3.81.0" # Check for the newest version here: https://registry.terraform.io/providers/DataDog/datadog/latest
    }
    vy = {
      source  = "nsbno/vy"
      version = ">= 1.0.0, < 2.0.0"
    }
  }
}

# DATADOG SETUP
module "datadog_provider_setup" {
  # Find newest version here: https://github.com/nsbno/terraform-datadog-provider-setup/releases
  source = "github.com/nsbno/terraform-datadog-provider-setup?ref=0.0.2"
}

provider "datadog" {
  api_key = module.datadog_provider_setup.api_key
  app_key = module.datadog_provider_setup.app_key

  api_url = "https://api.datadoghq.eu/"
}

provider "aws" {
  region = "eu-west-1"
}
