# Creating a VPC ID with SSM parameter store. 
resource "aws_ssm_parameter" "db_username" {
  name  = "${local.aws_ssm_username}/username"
  type  = "String"
  value = var.db_username
}

resource "aws_ssm_parameter" "db_password" {
  name  = "${local.aws_ssm_password}/password"
  type  = "SecureString"
  value = var.override
}

resource "aws_ssm_parameter" "db_endpoint" {
  name  = "${local.aws_ssm_endpoint}/endpoint"
  type  = "String"
  value = aws_db_instance.mydb.endpoint
}