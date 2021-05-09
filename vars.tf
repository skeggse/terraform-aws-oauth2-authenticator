terraform {
  experiments = [module_variable_optional_attrs]
}

variable "name" {
  type        = string
  description = "The name prefix for the entire workflow"
}

variable "parameter_prefix" {
  type = string
  validation {
    condition     = can(regex("^[a-zA-Z0-9_./-]*$", var.parameter_prefix))
    error_message = "Parameter names can only contain the characters `a-zA-Z0-9_./-`."
  }
}

variable "services" {
  type = map(
    object({
      client_id        = string
      secret_parameter = string
      extra_params     = optional(map(string))
      scopes           = set(string)

      # The web endpoint that serves as the starting point for the OAuth2.0 flow
      # Example: https://accounts.google.com/o/oauth2/v2/auth
      authorization_endpoint     = string
      token_endpoint             = string
      token_endpoint_auth_method = string

      identity_field       = string
      identify_with_openid = optional(bool)
      permitted_identities = set(string)
    })
  )
}
