terraform-aws-oauth2-authenticator
==================================

Generic single-tenant OAuth2.0 authenticator that puts tokens in Parameter Store.

```hcl
module "authorizer" {
  source = "github.com/skeggse/terraform-aws-oauth2-authenticator"

  # Prefix for resource names.
  name             = "authorizer"
  parameter_prefix = "/Dev/TenantCredentials"

  services = {
    google = {
      client_id                    = "EXAMPLE.apps.googleusercontent.com"
      client_secret_parameter_name = "/Dev/ServiceProviders/GoogleClient"
      extra_params = {
        access_type = "offline"
      }

      scopes = ["https://www.googleapis.com/auth/gmail.insert"]

      authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
      token_endpoint         = "https://oauth2.googleapis.com/token"

      token_endpoint_auth_method = "parameter"

      # Currently we check email_verified. This may be generalized at a later date.
      identity_field = "email"
      # Read the field from the id_token JWT, and request the "openid email" scope.
      identify_with_openid = true
      permitted_identities = ["user@example.com"]
    }

    fitbit = {
      client_id                    = "EXAMPLE"
      client_secret_parameter_name = "/Dev/ServiceProviders/FitbitClient"
      scopes    = ["heartrate"]

      authorization_endpoint = "https://www.fitbit.com/oauth2/authorize"
      token_endpoint         = "https://api.fitbit.com/oauth2/token"

      token_endpoint_auth_method = "header"

      identity_field       = "user_id"
      permitted_identities = ["26FWFL"]
    }
  }
}
```
