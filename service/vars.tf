variable "api_endpoint" {
  type = string
}

variable "api_id" {
  type = string
}

variable "api_integration_id" {
  type = string
}

variable "name" {
  type        = string
  description = "The name prefix for the entire workflow"
  validation {
    condition     = length(var.name) > 0
    error_message = "Name must not be blank."
  }
}

variable "service_name" {
  type = string
  validation {
    condition     = length(var.service_name) > 0
    error_message = "Service name must not be blank."
  }
}

variable "parameter_prefix" {
  type = string
  validation {
    condition     = can(regex("^[a-zA-Z0-9_./-]*$", var.parameter_prefix))
    error_message = "Parameter names can only contain the characters `a-zA-Z0-9_./-`."
  }
}

variable "client_id" {
  type = string
  validation {
    condition     = length(var.client_id) > 0
    error_message = "The client_id cannot be blank."
  }
}

# Unused in the module, just here for validation.
variable "secret_parameter" {
  type = string
  validation {
    condition     = can(regex("^[a-zA-Z0-9_./-]*$", var.secret_parameter))
    error_message = "Parameter names can only contain the characters `a-zA-Z0-9_./-`."
  }
}

variable "token_endpoint_auth_method" {
  type = string
  validation {
    condition     = contains(["parameter", "header"], var.token_endpoint_auth_method)
    error_message = "The mechanism by which the token endpoint authorizes requests must be defined in token_endpoint_auth_method as one of {\"parameter\", \"header\"}."
  }
}

variable "extra_params" {
  type    = map(string)
  default = {}
}

variable "scopes" {
  type    = set(string)
  default = []
}

# The web endpoint that serves as the starting point for the OAuth2.0 flow
# Example: https://accounts.google.com/o/oauth2/v2/auth
variable "authorization_endpoint" {
  type = string
  validation {
    condition     = can(regex("^https://[^?&]+$", var.authorization_endpoint))
    error_message = "The authorization_endpoint must be an https URL."
  }
}

variable "token_endpoint" {
  type = string
  validation {
    condition     = can(regex("^https://[^?&]+$", var.token_endpoint))
    error_message = "The token_endpoint must be an https URL."
  }
}

variable "identify_with_openid" {
  type    = bool
  default = false
}

variable "permitted_identities" {
  type = set(string)
  validation {
    condition     = length(var.permitted_identities) > 0
    error_message = "You must define permitted identities, otherwise this is a free-for-all."
  }
}
