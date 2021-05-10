terraform-aws-oauth2-authenticator
==================================

Generic single-tenant OAuth2.0 authenticator that puts tokens in Parameter
Store.

Overview
--------

This Terraform module implements a simple OAuth2.0 flow for custom single-tenant
applications. It is designed to authorize access to arbitrary service providers
(think Google, GitHub, Dropbox, Twitter) for a single identity at a time and
treat the authorization tokens as application secrets rather than protected user
data. This simplifies the process of setting up and managing access to your
personal information that's stored with external service providers.

Disclaimer: this module intentionally avoids defining `state` and `nonce`
parameters during the OAuth2.0 flow for simplicity. This is normally not
recommended, but in the context of this project it may be acceptable. Notably,
this project only manipulates exclusively server state (no client state is
modified), and only when valid authorization tokens corresponding to
pre-authorized users are presented.

Usage
-----

1. Configure your OAuth2.0 application with the service provider(s), and
   retrieve your application's client ID and secret pairs. Separately provision
   SSM parameters for the client credentials in json-encoded fields `client_id`
   and `client_secret`. In the example below, you'd create the
   `/Dev/ServiceProviders/GoogleClient` parameter with a value that looks like
   `{"client_id":"EXAMPLE.apps.googleusercontent.com","client_secret":"0cPppYgzfKdHyysI1sPpZF4N"}`.
2. Instantiate the auth module:

   ```hcl
   module "authorizer" {
     source = "github.com/skeggse/terraform-aws-oauth2-authenticator"

     # Prefix for resource names.
     name             = "authorizer"
     parameter_prefix = "/Dev/TenantCredentials"

     services = {
       google = {
         client_id        = "EXAMPLE.apps.googleusercontent.com"
         secret_parameter = "/Dev/ServiceProviders/GoogleClient"
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
         client_id        = "EXAMPLE"
         secret_parameter = "/Dev/ServiceProviders/FitbitClient"
         scopes           = ["heartrate"]

         authorization_endpoint = "https://www.fitbit.com/oauth2/authorize"
         token_endpoint         = "https://api.fitbit.com/oauth2/token"

         token_endpoint_auth_method = "header"

         identity_field       = "user_id"
         permitted_identities = ["26FWFL"]
       }
     }
   }
   ```

3. `terraform apply`
4. Take the `redirect_url` fields from the output (you can run
   `terraform output` to get the output again if you lost track of it), and
   define them as a valid redirect URLs for the service provider(s) you
   provisioned.
5. Visit the `initial_url` field for each service provider, and follow the
   prompts. You should see a message that says "Successfully stored new token."
6. (Optional) In your application, handle authorization failures from your API
   calls, and deliver an email to your inbox with a message explaining that your
   tokens have expired with a link to the `initial_url` field from this project.

Cost estimate
-------------

Disclaimer: use this module at your own risk. This estimate is best-effort, and
your mileage may vary. See the LICENSE file for legal disclaimers.

Most personal deployments of this module will see costs from the following resources:

* AWS Lambda, up to $0.0002502/login (likely only $0.0000127/login)
* API Gateway, $0.000001/login
* CloudWatch Logs, up to $0.000001/login

You theoretically only need to do this once per service provider, but may
realistically need to do this once per month. This means you're paying only a
quarter of a tenth of a cent. This assumes you're only using the standard tier
and standard throughput for parameters in parameter store, that you're using the
default SSM KMS key, and that your CloudWatch usage doesn't exceed the free
tier.
