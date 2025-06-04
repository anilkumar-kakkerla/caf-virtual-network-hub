terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0" # or your specific version
    }
  }
}

provider "azurerm" {
  features {}
}
