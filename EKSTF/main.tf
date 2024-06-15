##########################################################################################################################
################################################   EKS Resources   #######################################################
##########################################################################################################################

# create the IAM role for EKS
resource "aws_iam_role" "myk8s_role" {
  name               = "Myk8sRole"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

# Attach the EKS service policy to the role
resource "aws_iam_role_policy_attachment" "myk8s-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.myk8s_role.name
}

#cluster provision
resource "aws_eks_cluster" "mywebsite_cluster" {
  name     = "k8s-web-cluster"
  role_arn = aws_iam_role.myk8s_role.arn

  vpc_config {
    subnet_ids = data.aws_subnets.public.ids
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.myk8s-AmazonEKSClusterPolicy,
  ]
}

# Create Node Grroup
resource "aws_iam_role" "myk8s-node" {
  name = "myk8s-node-group-cloud"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

# Attach Policies
resource "aws_iam_role_policy_attachment" "myk8sNode-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.myk8s-node.name
}

resource "aws_iam_role_policy_attachment" "myk8sCNI-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.myk8s-node.name
}

resource "aws_iam_role_policy_attachment" "myk8sECR-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.myk8s-node.name
}


resource "aws_security_group" "eks_node_sg" {
  name        = "eks-node-sg"
  description = "Allow inbound/outbound traffic for EKS nodes"
  vpc_id      = data.aws_vpc.default.id
}

# Allow inbound traffic for nodes
resource "aws_security_group_rule" "eks_node_inbound" {
  description       = "Allow inbound traffic for EKS nodes"
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.eks_node_sg.id
}

# Allow outbound traffic for nodes
resource "aws_security_group_rule" "eks_node_outbound" {
  description       = "Allow outbound traffic for EKS nodes"
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.eks_node_sg.id
}


# create node group
resource "aws_eks_node_group" "myk8s_node_grp" {
  cluster_name    = aws_eks_cluster.mywebsite_cluster.name
  node_group_name = "k8s-website_Node-cloud"
  node_role_arn   = aws_iam_role.myk8s-node.arn
  subnet_ids      = data.aws_subnets.public.ids

  scaling_config {
    desired_size = var.ec2_scaling[0]
    max_size     = var.ec2_scaling[1]
    min_size     = var.ec2_scaling[0]
  }
  instance_types = var.eks_instance_type

  # Associate the EKS node group with the correct security group
  remote_access {
    ec2_ssh_key               = data.aws_key_pair.instance_connect_keypair.key_name
    source_security_group_ids = [aws_security_group.eks_node_sg.id]
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.myk8sNode-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.myk8sCNI-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.myk8sECR-AmazonEC2ContainerRegistryReadOnly,
  ]
}

##########################################################################################################################
################################################   ECR Resources   #######################################################
##########################################################################################################################

# Create Elastic Container Registry Repo 
resource "aws_ecr_repository" "my_ecr" {
  name                 = "${var.name}-ecr"
  image_tag_mutability = var.muta

  image_scanning_configuration {
    scan_on_push = var.scan
  }
}

##########################################################################################################################
######################################################## RDS #############################################################
##########################################################################################################################

# RDS Subnet Group
resource "aws_db_subnet_group" "private_db_subnet" {
  name        = "mysql-rds-private-subnet-group"
  description = "Private subnets for RDS instance"
  subnet_ids  = data.aws_subnets.private.ids
}

# RDS Security Group
resource "aws_security_group" "rds_sg" {
  name        = "${var.db_name}-rds-sg"
  description = "Allow inbound/outbound MySQL traffic"
  vpc_id      = data.aws_vpc.default.id
  depends_on  = [data.aws_vpc.default]
}

# Allow inbound MySQL connections from EKS Node Groups
resource "aws_security_group_rule" "allow_mysql_in" {
  description              = "Allow inbound MySQL connections"
  type                     = "ingress"
  from_port                = "3306"
  to_port                  = "3306"
  protocol                 = "tcp"
  # cidr_blocks              = var.eks_node_cidr_blocks
  source_security_group_id = aws_security_group.eks_node_sg.id
  security_group_id        = aws_security_group.rds_sg.id
}

# Allow inbound MySQL connections from my IP
resource "aws_security_group_rule" "allow_mysql_in_my_ip" {
  description       = "Allow inbound MySQL connections from my IP"
  type              = "ingress"
  from_port         = 3306
  to_port           = 3306
  protocol          = "tcp"
  cidr_blocks       = var.ssh_cidr # using my ip
  security_group_id = aws_security_group.rds_sg.id
}

# Allow inbound MySQL connections from EKS Node Groups
resource "aws_security_group_rule" "allow_ec2_in_mysql_db" {
  description              = "Allow inbound MySQL connections"
  type                     = "ingress"
  from_port                = "3306"
  to_port                  = "3306"
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.instance_connect_sg.id
  security_group_id        = aws_security_group.rds_sg.id
}

# Allow outbound traffic from RDS to anywhere (optional, based on your requirements)
resource "aws_security_group_rule" "allow_mysql_out" {
  description       = "Allow outbound traffic from RDS"
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.rds_sg.id
}

resource "random_password" "password" {
  length           = var.length
  special          = var.special
  override_special = var.override
}

resource "aws_db_instance" "mydb" {
  identifier           = var.name
  allocated_storage    = var.storage
  db_name              = var.name
  engine               = var.engine
  engine_version       = var.engine_version
  instance_class       = var.instance_class
  username             = aws_ssm_parameter.db_username.value
  password             = aws_ssm_parameter.db_password.value
  parameter_group_name = var.parameter_group_name
  skip_final_snapshot  = var.skip_final_snapshot
  publicly_accessible  = var.access_db

  # Associate RDS with the subnet group
  db_subnet_group_name = aws_db_subnet_group.private_db_subnet.name

  # Use the security group associated with EC2 instances
  vpc_security_group_ids = [aws_security_group.rds_sg.id]

  tags = {
    Name = "${var.name}-instance"
  }

}

##########################################################################################################################
############################################# EC2 Instance Connnect ######################################################
##########################################################################################################################

resource "aws_security_group" "instance_connect_sg" {
  name        = "${var.name}-instance-connect-sg"
  description = "Default security group to allow inbound/outbound from the VPC"
  vpc_id      = data.aws_vpc.default.id
  depends_on  = [data.aws_vpc.default]
}

# Allow inbound SSH for EC2 instances
resource "aws_security_group_rule" "allow_ssh_in" {
  description       = "Allow SSH"
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.instance_connect_sg.id
}

resource "aws_security_group_rule" "allow_https_in_api" {
  description       = "Allow inbound HTTPS traffic from my ip"
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.instance_connect_sg.id
}

resource "aws_security_group_rule" "allow_http_in_api" {
  description       = "Allow inbound HTTP traffic from my IP"
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.instance_connect_sg.id
}

# Allow all outbound traffic
resource "aws_security_group_rule" "allow_all_out" {
  description       = "Allow outbound traffic"
  type              = "egress"
  from_port         = "0"
  to_port           = "0"
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.instance_connect_sg.id
}

resource "aws_instance" "db_instance_connect" {
  ami                         = data.aws_ami.ubuntu_latest.id
  instance_type               = var.db_instance_type
  subnet_id                   = data.aws_subnet.public_selected.id
  associate_public_ip_address = true
  key_name                    = data.aws_key_pair.instance_connect_keypair.key_name
  iam_instance_profile        = aws_iam_instance_profile.instance_profile.name

  vpc_security_group_ids = [
    aws_security_group.instance_connect_sg.id
  ]
  root_block_device {
    delete_on_termination = true
    # iops                = 150 # only valid for volume_type io1
    volume_size = var.storage
    volume_type = var.storage_type
  }
  tags = {
    Name = "${var.name}-db_instance_connect"
    OS   = var.os
  }

  depends_on = [aws_security_group.instance_connect_sg]

  user_data = base64encode(templatefile("userdata.sh", {
    DB_USER           = aws_ssm_parameter.db_username.value
    DB_PASSWORD_PARAM = aws_ssm_parameter.db_password.value
    DB_HOST           = aws_db_instance.mydb.address
    DB_PORT           = aws_security_group_rule.allow_mysql_in.from_port
    DB_NAME           = aws_db_instance.mydb.db_name
  }))
}

# Create an IAM instance profile for the EC2 instance
resource "aws_iam_instance_profile" "instance_profile" {
  name = "ec2-instance-connect-profile"
  role = aws_iam_role.instance_role.name
}

# Create an IAM role for the EC2 instance
resource "aws_iam_role" "instance_role" {
  name = "ec2-instance-connect-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

# Attach the necessary IAM policy to the instance role
resource "aws_iam_role_policy_attachment" "instance_policy_attachment" {
  role       = aws_iam_role.instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess"
}

# Create an IAM instance profile for the EC2 instance to use the IAM role
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "ec2_ssm_instance_profile"
  role = aws_iam_role.ec2_role.name
}

# Creates an IAM role with the trust policy allowing EC2 to assume the role
resource "aws_iam_role" "ec2_role" {
  name = "ec2_ssm_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Defines a policy allowing the EC2 instance to fetch parameters from the SSM Parameter Store
resource "aws_iam_policy" "ssm_policy" {
  name        = "ssm_parameter_store_policy"
  description = "Policy to allow access to SSM Parameter Store"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach Policy to Role: Attaches the policy to the IAM role
resource "aws_iam_role_policy_attachment" "ssm_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.ssm_policy.arn
}

##########################################################################################################################
###################################################### Route53 DNS #######################################################
##########################################################################################################################

# Create Route 53 hosted zone
resource "aws_route53_zone" "main" {
  name = var.domain_name
}

# Create an alias record for www
resource "aws_route53_record" "success" {
  zone_id = aws_route53_zone.main.zone_id
  name    = var.record_name[0]
  type    = var.record_type
  alias {
    name                   = data.aws_lb.nlb.dns_name
    zone_id                = data.aws_lb.nlb.zone_id
    evaluate_target_health = var.eval_target_health
  }
}

# Create an alias record for root domain
resource "aws_route53_record" "root" {
  zone_id = aws_route53_zone.main.zone_id
  name    = var.record_name[1]
  type    = var.record_type
  alias {
    name                   = data.aws_lb.nlb.dns_name
    zone_id                = data.aws_lb.nlb.zone_id
    evaluate_target_health = var.eval_target_health
  }
}

# Create an alias record for awsblog
resource "aws_route53_record" "aswblog" {
  zone_id = aws_route53_zone.main.zone_id
  name    = var.record_name[2]
  type    = var.record_type
  alias {
    name                   = data.aws_lb.nlb.dns_name
    zone_id                = data.aws_lb.nlb.zone_id
    evaluate_target_health = var.eval_target_health
  }
}







