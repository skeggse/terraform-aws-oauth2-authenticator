data "aws_iam_policy_document" "callback-invoke" {
  statement {
    effect  = "Allow"
    actions = ["lambda:InvokeFunction"]
    # TODO: specify version?
    resources = [aws_lambda_function.callback.arn]
  }
}

data "aws_iam_policy_document" "apigateway-assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["apigateway.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "callback-invoke" {
  name = "${var.name}-callback-invoke"

  policy      = data.aws_iam_policy_document.callback-invoke.json
  description = "Invoke the callback Lambda"
}

resource "aws_iam_role_policy_attachment" "callback-invoke" {
  role       = aws_iam_role.callback-invoke.name
  policy_arn = aws_iam_policy.callback-invoke.arn
}

resource "aws_iam_role" "callback-invoke" {
  name = "${var.name}-callback-invoke"

  assume_role_policy = data.aws_iam_policy_document.apigateway-assume.json
  description        = "Invoke the callback Lambda from the callback endpoints"
}
