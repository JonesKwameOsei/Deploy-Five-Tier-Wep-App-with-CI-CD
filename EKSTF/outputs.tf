# Output for IAM Role ID and ARN
output "iam_role_id" {
  value = aws_iam_role.myk8s_role.id
}

output "iam_role_arn" {
  value = aws_iam_role.myk8s_role.arn
}

# Output for EKS Node Group ID and ARN
output "eks_node_group_id" {
  value = aws_eks_node_group.myk8s_node_grp.id
}

output "eks_node_group_arn" {
  value = aws_eks_node_group.myk8s_node_grp.arn
}

# Outputs for EKS Cluster ID and ARN
output "eks_cluster_id" {
  value = aws_eks_cluster.mywebsite_cluster.id
}

output "eks_cluster_arn" {
  value = aws_eks_cluster.mywebsite_cluster.arn
}

# Output for MySQL RDS
output "rds_instance_id" {
  value = aws_db_instance.mydb.id
}

output "ec2_public_ipv4" {
  value = aws_instance.db_instance_connect.public_ip
}

output "ec2_id" {
  value = aws_instance.db_instance_connect.id
}


output "rds_sg_id" {
  value       = aws_security_group.rds_sg.id
  description = "The ID of the RDS security group"
}

output "rds_private_endpoint" {
  value = aws_db_instance.mydb.endpoint
}

# Output the IAM Instance Profile
output "ec2_instance_profile" {
  description = "The IAM instance profile for the EC2 instance"
  value       = aws_iam_instance_profile.ec2_instance_profile.arn
}

# Output the IAM Role
output "ec2_role" {
  description = "The IAM role for the EC2 instance"
  value       = aws_iam_role.ec2_role.arn
}

# Output the IAM Policy
output "ssm_policy" {
  description = "The IAM policy to allow access to SSM Parameter Store"
  value       = aws_iam_policy.ssm_policy.arn
}

# Output the EC2 Instance Security Group ID
output "ec2_instance_sg_id" {
  description = "Security group ID for the EC2 instance"
  value       = aws_security_group.instance_connect_sg.id
}

# Output the RDS Instance Security Group ID
output "rds_instance_sg_id" {
  description = "Security group ID for the RDS instance"
  value       = aws_security_group.rds_sg.id
}

# Output the EC2 Instance ID
output "ec2_instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.db_instance_connect.id
}

# Output the RDS Endpoint
output "rds_endpoint" {
  description = "Endpoint of the RDS instance"
  value       = aws_db_instance.mydb.endpoint
}

