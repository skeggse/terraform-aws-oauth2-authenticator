data "aws_iam_policy_document" "callback-policy" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.callback-logs.arn}:*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
    ]
    resources = [
      for _, config in var.services :
      "arn:aws:ssm:${local.local_arn_infix}:parameter/${trimprefix(config.client_secret_parameter_name, "/")}"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "ssm:PutParameter",
    ]
    resources = ["arn:aws:ssm:${local.local_arn_infix}:parameter/${trimprefix(local.parameter_prefix, "/")}/*"]
  }
}

data "aws_iam_policy_document" "assume-callback-policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "callback-policy" {
  name   = "${var.name}-policy"
  policy = data.aws_iam_policy_document.callback-policy.json
}

resource "aws_iam_role" "callback-role" {
  name               = var.name
  assume_role_policy = data.aws_iam_policy_document.assume-callback-policy.json
  description        = "Allow the ${local.function_name} Lambda to read and put parameters to support the ${var.name} system."
}

resource "aws_iam_role_policy_attachment" "callback" {
  role       = aws_iam_role.callback-role.name
  policy_arn = aws_iam_policy.callback-policy.arn
}
