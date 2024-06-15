data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

#get vpc data
data "aws_vpc" "default" {
  default = true
}
#get public subnets for cluster
data "aws_subnets" "public" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

#get public subnets for cluster
data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Fetch a single subnet
data "aws_subnet" "public_selected" {
  id = "subnet-04380788995312511"
}

# Fetch ami from canonical 
data "aws_ami" "ubuntu_latest" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_key_pair" "instance_connect_keypair" {
  key_name = "MyK8sKeyPair"
}

# Get the NLB Hosted Zone ID
# Get the NLB details

data "aws_lb" "nlb" {
  arn  = var.lb_arn
  name = var.lb_name
}

# Get the NLB Hosted Zone ID
# data "aws_lb" "nlb_zone_id" {
#   id = "Z2IFOLAFXWLO4F"
# }

# Get EKS ec grps
data "aws_eks_cluster" "eks-sg" {
  name = "eks-cluster-sg-k8s-web-cluster-1180347930"
}
