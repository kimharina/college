# 1.Provider 선언
terraform {
  required_providers {
    aws = {
      version = "~> 5.0"
      source  = "hashicorp/aws"
    }
  }
}
provider "aws" {
  region  = "ap-northeast-2"
  profile = "root"
}

# 2. VPC, Subnet
module "vpc" {
  source          = "terraform-aws-modules/vpc/aws"
  version         = "~> 5.0"
  name            = "college-vpc"
  cidr            = "192.168.0.0/16"
  azs             = ["ap-northeast-2a", "ap-northeast-2c"]
  private_subnets = ["192.168.1.0/24", "192.168.2.0/24"]
  public_subnets  = ["192.168.10.0/24", "192.168.20.0/24"]
}

# 3. ECR
resource "aws_ecr_repository" "foo" {
  name = "college"

  image_scanning_configuration {
    scan_on_push = false
  }
}

# 4.EKS
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"

  # 4-1.EKS Cluster Setting
  cluster_name    = "college-eks"
  cluster_version = "1.28"
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnets

  # 4-2.OIDC(OpenID Connect) 구성 
  enable_irsa = true

  # 4-3.EKS Worker Node 정의 ( ManagedNode방식 / Launch Template 자동 구성 )
  eks_managed_node_groups = {
    college_WorkerNode = {
      instance_types         = ["t3.large"]
      min_size               = 1
      max_size               = 3
      desired_size           = 2
      vpc_security_group_ids = [module.add_node_sg.security_group_id]
    }
  }

  # 4-4.public-subnet(bastion)과 API와 통신하기 위해 설정(443)
  cluster_additional_security_group_ids = [module.add_cluster_sg.security_group_id]
  cluster_endpoint_public_access        = true

  # K8s ConfigMap Object "aws_auth" 구성
  manage_aws_auth_configmap = true
  aws_auth_users = [
    {
      userarn  = "arn:aws:iam::${data.aws_iam_user.EKS_Admin_ID.id}:user/root"
      username = "root"
      groups   = ["system:masters"]
    },
  ]
}

# 5.kubernetes provider 선언
provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name, "--profile", "root"]
  }
}
# 6.Kubernetes Account와 연결할 AWS 계정
data "aws_iam_user" "EKS_Admin_ID" {
  user_name = "root"
}

# 7.보안그룹
# 7-1. cluster 보안그룹
module "add_cluster_sg" {
  source      = "terraform-aws-modules/security-group/aws"
  version     = "~> 5.0"
  name        = "add_cluster_sg"
  description = "add_cluster_sg"

  vpc_id          = module.vpc.vpc_id
  use_name_prefix = false

  ingress_with_cidr_blocks = [
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = module.vpc.vpc_cidr_block
    }
  ]
  egress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = "0.0.0.0/0"
    }
  ]
}
# 7-2. Worker Node 보안그룹
module "add_node_sg" {
  source      = "terraform-aws-modules/security-group/aws"
  version     = "~> 5.0"
  name        = "add_node_sg"
  description = "add_node_sg"

  vpc_id          = module.vpc.vpc_id
  use_name_prefix = false

  ingress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = module.vpc.vpc_cidr_block
    }
  ]
  egress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = "0.0.0.0/0"
    }
  ]
}
# 7-3. Bastion 보안그룹
module "BastionHost_SG" {
  source          = "terraform-aws-modules/security-group/aws"
  version         = "~> 5.0"
  name            = "BastionHost_SG"
  description     = "BastionHost_SG"
  vpc_id          = module.vpc.vpc_id
  use_name_prefix = false

  ingress_with_cidr_blocks = [
    {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 3000
      to_port     = 3000
      protocol    = "tcp"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = -1
      to_port     = -1
      protocol    = "icmp"
      cidr_blocks = "0.0.0.0/0"
    }
  ]
  egress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = "0.0.0.0/0"
    }
  ]
}
# 7-4. Public 보안그룹
module "Public_SG" {
  source          = "terraform-aws-modules/security-group/aws"
  version         = "~> 5.0"
  name            = "Public_SG"
  description     = "Public_SG"
  vpc_id          = module.vpc.vpc_id
  use_name_prefix = false

  ingress_with_cidr_blocks = [
    {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = -1
      to_port     = -1
      protocol    = "icmp"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 8080
      to_port     = 8080
      protocol    = "tcp"
      cidr_blocks = "0.0.0.0/0"
    }
  ]
  egress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = "0.0.0.0/0"
    }
  ]
}
# 7-5.Nat 보안그룹
module "NAT_SG" {
  source          = "terraform-aws-modules/security-group/aws"
  version         = "~> 5.0"
  name            = "NAT_SG"
  vpc_id          = module.vpc.vpc_id
  use_name_prefix = false

  ingress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = module.vpc.private_subnets_cidr_blocks[0]
    },
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = module.vpc.private_subnets_cidr_blocks[1]
    }
  ]
  egress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = "0.0.0.0/0"
    }
  ]
}
# 7-6. DB 보안그룹
module "DB_sg" {
  source      = "terraform-aws-modules/security-group/aws"
  version     = "~> 5.0"
  name        = "DB_sg"
  description = "DB_sg"

  vpc_id          = module.vpc.vpc_id
  use_name_prefix = false

  ingress_with_cidr_blocks = [
    {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = module.vpc.vpc_cidr_block
    },
    {
      from_port   = 3306
      to_port     = 3306
      protocol    = "tcp"
      cidr_blocks = "0.0.0.0/0"
    }
  ]
  egress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = "0.0.0.0/0"
    }
  ]
}

# 8.ec2 Key-pair
data "aws_key_pair" "ec2-key" {
  key_name = "college"
}


# 9.EC2 생성
# 9-1.Bastion
resource "aws_instance" "BastionHost" {
  ami                         = "ami-0bc4327f3aabf5b71"
  instance_type               = "t2.medium"
  key_name                    = data.aws_key_pair.ec2-key.key_name
  subnet_id                   = module.vpc.public_subnets[0]
  associate_public_ip_address = true
  vpc_security_group_ids      = [module.BastionHost_SG.security_group_id]

  tags = {
    Name = "BastionHost_Instance"
  }
}

# 9-2.NAT
resource "aws_instance" "nat_ec2" {
  ami                         = "ami-0f4c2e6aee30ccae8"
  subnet_id                   = module.vpc.public_subnets[1]
  instance_type               = "t2.micro"
  key_name                    = data.aws_key_pair.ec2-key.key_name
  source_dest_check           = false
  associate_public_ip_address = true
  vpc_security_group_ids      = [module.NAT_SG.security_group_id]
  tags = {
    Name = "nat-ec2"
  }
}

# 9-3.Jenkins
# resource "aws_instance" "Jenkins-EC2" {
#   ami           = "ami-040ee211cab253675"
#   instance_type = "t3.large"
#   key_name = "project_key"
#   associate_public_ip_address = true
#   subnet_id = module.vpc.public_subnets[0]
#   vpc_security_group_ids = [module.Public_SG.security_group_id]
#     tags = {
#       Name = "EC2-jenkins"
#     }
# }

# 10.라우팅 테이블
# 10-1.Private Routing Table
# Private Subnet Routing Table ( dest: NAT Instance ENI )
data "aws_route_table" "private_0" {
  subnet_id  = module.vpc.private_subnets[0]
  depends_on = [module.vpc]
}

data "aws_route_table" "private_1" {
  subnet_id  = module.vpc.private_subnets[1]
  depends_on = [module.vpc]
}

resource "aws_route" "private_subnet_0" {
  route_table_id         = data.aws_route_table.private_0.id
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id   = aws_instance.nat_ec2.primary_network_interface_id
  depends_on             = [module.vpc, aws_instance.nat_ec2]
}

resource "aws_route" "private_subnet_1" {
  route_table_id         = data.aws_route_table.private_1.id
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id   = aws_instance.nat_ec2.primary_network_interface_id
  depends_on             = [module.vpc, aws_instance.nat_ec2]
}

// Private Subnet Tag ( AWS Load Balancer Controller Tag / internal )
resource "aws_ec2_tag" "private_subnet_tag1" {
  resource_id = module.vpc.private_subnets[0]
  key         = "kubernetes.io/role/internal-elb"
  value       = "1"
}
resource "aws_ec2_tag" "private_subnet_tag2" {
  resource_id = module.vpc.private_subnets[1]
  key         = "kubernetes.io/role/internal-elb"
  value       = "1"
}

// Public Subnet Tag ( AWS Load Balancer Controller Tag / internet-facing )
resource "aws_ec2_tag" "public_subnet_tag1" {
  resource_id = module.vpc.public_subnets[0]
  key         = "kubernetes.io/role/elb"
  value       = "1"
}
resource "aws_ec2_tag" "public_subnet_tag2" {
  resource_id = module.vpc.public_subnets[1]
  key         = "kubernetes.io/role/elb"
  value       = "1"
}

output "bastion_ip" {
  value       = aws_instance.BastionHost.public_ip
  description = "bastion-host public IP"
}

# 11. Bastion AutoScaling
# resource "aws_launch_template" "bastion-Template" {

#   name_prefix   = "college-as"
#   image_id      = "ami-057ec42830b20bc2c"
#   instance_type = "t2.micro"
#   key_name = "project_key"

#   network_interfaces {
#     associate_public_ip_address = true
#   }

# }

# resource "aws_autoscaling_group" "college-autoscaling" {
#   vpc_zone_identifier = [module.vpc.public_subnets[0],module.vpc.public_subnets[1]]
#   desired_capacity   = 1
#   max_size           = 2
#   min_size           = 1

#   launch_template {
#     id      = aws_launch_template.bastion-Template.id
#     version = "$Latest"


#   }

#   tag {
#     key                 = "Name"
#     value               = "AS-Bastion"
#     propagate_at_launch = true
#   }

# }

# 12.DB Subnet Group
resource "aws_db_subnet_group" "college-db-subnet-group" {
  name       = "main"
  subnet_ids = [module.vpc.private_subnets[0], module.vpc.private_subnets[1]]

  tags = {
    Name = "college-db-subnet-group"
  }
} 