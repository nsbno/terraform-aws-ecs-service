terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.15.0, < 7.0.0"
    }
    vy = {
      source  = "nsbno/vy"
      version = ">= 1.0.0, < 2.0.0"
    }
  }
}


provider "aws" {
  region = "eu-west-1"
}

provider "vy" {
  environment = "test"
}
