variable "aws_region" {
  description = "AWS region For EVI deployment"
  type        = string
  default     = "ap-south-1"

}

variable "project_name" {
  description = "Name prefix for all EVI resources"
  type        = string
  default     = "evi"
}

variable "openrouter_api_key" {
  description = "OpenRouter API key used by the EVI backend"
  type        = string
  sensitive   = true
}

variable "flask_secret_key" {
  description = "Flask secret key used for session signing"
  type        = string
  sensitive   = true
}