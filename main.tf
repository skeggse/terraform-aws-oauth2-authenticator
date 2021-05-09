locals {
  account_id      = data.aws_caller_identity.current.account_id
  local_arn_infix = "${data.aws_region.current.name}:${local.account_id}"
  function_name   = var.name
  parameter_prefix = (
    can(regex("[^/]", var.parameter_prefix))
    ? trimsuffix(var.parameter_prefix, "/")
    : var.parameter_prefix
  )
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_apigatewayv2_api" "interface" {
  name          = var.name
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.interface.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_apigatewayv2_integration" "callback" {
  api_id           = aws_apigatewayv2_api.interface.id
  description      = "Accept the authorized/rejected user authorization request, and if authenticated store the new refresh token"
  integration_type = "AWS_PROXY"

  connection_type        = "INTERNET"
  integration_method     = "POST"
  integration_uri        = aws_lambda_function.callback.arn
  payload_format_version = "2.0"
  credentials_arn        = aws_iam_role.callback-invoke.arn
}

resource "aws_cloudwatch_log_group" "callback-logs" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 90
}

data "archive_file" "callback-bundle" {
  type        = "zip"
  output_path = "${path.module}/callback-bundle.zip"

  source {
    content  = file("${path.module}/callback.py")
    filename = "main.py"
  }
}

resource "aws_lambda_function" "callback" {
  function_name = local.function_name
  role          = aws_iam_role.callback-role.arn

  publish          = true
  filename         = data.archive_file.callback-bundle.output_path
  source_code_hash = data.archive_file.callback-bundle.output_base64sha256
  handler          = "main.lambda_handler"
  # TODO: bundle the requests module before upgrading this.
  # https://aws.amazon.com/blogs/compute/upcoming-changes-to-the-python-sdk-in-aws-lambda/
  runtime = "python3.7"

  timeout     = 60
  memory_size = 256

  environment {
    variables = {
      SERVICES = jsonencode({
        for service_name, config in var.services :
        service_name => {
          client_id                    = config.client_id
          client_secret_parameter_name = config.client_secret_parameter_name
          # TODO: fix dependency cycle
          parameter_name             = "${local.parameter_prefix}/${service_name}" # module.services[service_name].secret_parameter
          identity_field             = config.identity_field
          permitted_identities       = config.permitted_identities
          token_endpoint             = config.token_endpoint
          token_endpoint_auth_method = config.token_endpoint_auth_method
        }
      })
    }
  }
}


module "services" {
  for_each = var.services
  source   = "./service"

  name                   = var.name
  service_name           = each.key
  client_id              = each.value.client_id
  extra_params           = each.value.extra_params
  scopes                 = each.value.scopes
  authorization_endpoint = each.value.authorization_endpoint
  token_endpoint         = each.value.token_endpoint
  permitted_identities   = each.value.permitted_identities
  parameter_prefix       = local.parameter_prefix

  api_id             = aws_apigatewayv2_api.interface.id
  api_integration_id = aws_apigatewayv2_integration.callback.id
  api_endpoint       = aws_apigatewayv2_api.interface.api_endpoint
}

output "service_urls" {
  value = {
    for service_name, config in var.services :
    # Typically the service that provided the client_id and client_secret will need the redirect_uri
    # configured before its authorization flow will work.
    service_name => module.services[service_name].urls
  }
}
