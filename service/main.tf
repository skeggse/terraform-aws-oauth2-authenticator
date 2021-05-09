resource "aws_apigatewayv2_route" "route" {
  api_id    = var.api_id
  route_key = "GET ${local.callback_route}"
  target    = "integrations/${var.api_integration_id}"
}

locals {
  callback_route = "/${urlencode(var.service_name)}/callback"
  redirect_uri   = "${var.api_endpoint}${local.callback_route}"

  # We don't use state here. If you know much about the OAuth2.0 protocol, you know that's typically
  # a bad idea. We're ok with this because there is no client! This entire workflow is designed
  # around storing a refresh token in a central location to facilitate offline access to privileged
  # user APIs in a single-tenant model
  initial_params = merge(
    var.extra_params,
    {
      # Place this first to make it most visible in the URL the user will visit. It's especially
      # important that you (the user) look closely at the link you're clicking to make sure you're
      # authenticating your account against this authenticator and not against a malicious service.
      redirect_uri  = local.redirect_uri
      client_id     = var.client_id
      prompt        = "consent"
      response_type = "code"
      scope = (
        join(" ", setunion(var.scopes, var.identify_with_openid ? ["openid email"] : []))
      )
    }
  )

  encoded_initial_params = join("&", [
    for field, value in local.initial_params :
    "${urlencode(field)}=${urlencode(value)}"
  ])

  initial_url = "${var.authorization_endpoint}?${local.encoded_initial_params}"
}

output "urls" {
  value = {
    initial_url = local.initial_url
    initial_url_with_login_hint = (
      length(var.permitted_identities) == 1
      ? "${local.initial_url}&login_hint=${urlencode(tolist(var.permitted_identities)[0])}"
      : local.initial_url
    )

    # Typically the service that provided the client_id and client_secret will need this configured
    # before this authorization flow will work.
    redirect_uri = local.redirect_uri
  }
}
