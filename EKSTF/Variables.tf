# Variables configirations 
# The following are the default values for the configuration variables

# Variables definitions for EKS
variable "name" {
  type        = string
  description = "name for resources"
  default     = "jones"
}

variable "eks_instance_type" {
  type        = list(string)
  description = "Types of EC2 Instances for different purposes"
  default     = ["t2.medium"]
}


variable "ec2_scaling" {
  type        = list(number)
  description = "Number of EC2 instances to run in the EKS cluster"
  default     = [3, 5]
}

# Variables for ECR 
variable "muta" {
  type        = string
  description = "The tag mutability setting for the repository"
  default     = "MUTABLE"
}

variable "scan" {
  type        = bool
  description = "Indicates whether images are scanned after push"
  default     = true
}

# Variables description for RDS
variable "db_name" {
  type        = string
  description = "Name of the RDS database"
  default     = "jones-db"
}

variable "storage" {
  type        = number
  description = "Storage size for RDS database"
  default     = 20
}

variable "engine" {
  type        = string
  description = "Database engine"
  default     = "mysql"
}

variable "engine_version" {
  type        = string
  description = "Database engine version"
  default     = "8.0"
}

variable "instance_class" {
  type        = string
  description = "Instance class for RDS database"
  default     = "db.t3.micro"
}

variable "db_username" {
  type        = string
  description = "Username for RDS database"
  default     = "dbuser"
}

variable "override" {
  type        = string
  description = "Password for RDS database"
  default     = "yourpasss"
}

variable "length" {
  description = "Length of the resource."
  type        = number
  default     = 16
}

variable "special" {
  description = "Whether to include special characters."
  type        = bool
  default     = true
}


variable "parameter_group_name" {
  type        = string
  description = "Parameter group name for RDS database"
  default     = "default.mysql8.0"
}

variable "skip_final_snapshot" {
  type        = bool
  description = "Skip final snapshot"
  default     = true
}

variable "access_db" {
  type        = bool
  description = "Access to database"
  default     = true
}

# variables for RDS Security Group CIDR Blocks 
variable "eks_node_cidr_blocks" {
  type        = list(string)
  description = "CIDR blocks for EKS nodes"
  default     = ["*****/20", "********/20", "*********/20", "*******/20"]
}

variable "ssh_cidr" {
  type        = list(string)
  description = "CIDR block for your IP address"
  default     = ["urip/32"]
}

# variables for EC2 Instance Connect
variable "storage_type" {
  type        = string
  description = "Storage type for EC2 DB Instance Connect"
  default     = "gp2"
}

variable "db_instance_type" {
  type        = string
  description = "Types of EC2 Instances for different purposes"
  default     = "t2.micro"
}

variable "os" {
  type        = string
  description = "Operating System for EC2 DB Instance Connect"
  default     = "ubuntu"
}

# variable "rsa_bits" {
#   type        = number
#   description = "bitsize for encryption keypairs"
#   default     = 4096
# }

# variable "algorithm" {
#   type        = string
#   description = "Algorithm type of encryprion"
#   default     = "RSA"
# }

# variable "file_perm" {
#   type        = string
#   description = "File permission on encryption keypair"
# }

# variable "dir_perm" {
#   type        = string
#   description = "Permission for the directory in which the file is"
# }

# Variables for Route53 configuration
variable "lb_arn" {
  type    = string
  default = "***********************************************************************************************************"
}

variable "lb_name" {
  type    = string
  default = "**************************************"
}

variable "domain_name" {
  type        = string
  description = "Domain name for Route53 configuration"
  default     = "jonestecsolutions.com"
}

variable "record_name" {
  type        = list(any)
  description = "Record name for Route53 configuration"
  default     = ["success.jonestecsolutions.com", "jonestecsolutions.com", "awsblog.jonestecsolutions.com"]
}

variable "record_type" {
  type        = string
  description = "Record type for Route53 configuration"
  default     = "A"
}

variable "eval_target_health" {
  type        = bool
  description = "Evaluate target health for Route53 configuration"
  default     = false
}











