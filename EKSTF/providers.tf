terraform {
  #   terraform {
  #   backend "s3" {
  #     bucket = "jones-shiny-tfbucket" # The S3 bucket bucket we created
  #     key    = "EKS/terraform.tfstate"
  #     region = "eu-west-1"
  #   }
  # }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "eu-west-1"
}