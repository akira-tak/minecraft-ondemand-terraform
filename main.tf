
resource "aws_ecs_cluster" "this" {
  name = "minecraft-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_iam_role" "ecs_role" {
  name = "ecs_minecraft_service_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ecs.amazonaws.com"
        }
      },
    ]
  })

}

resource "aws_iam_role_policy" "ecs_minecraft_service_policy" {
  name = "ecs_minecraft_service_policy"
  role = aws_iam_role.ecs_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ecs:*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [
          "ec2:DescribeNetworkInterfaces",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role" "ecs_task_role" {
  name = "ecs_minecraft_task_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      },
    ]
  })

}

resource "aws_iam_role_policy" "ecs_minecraft_task_policy" {
  name = "ecs_minecraft_task_policy"
  role = aws_iam_role.ecs_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "elasticfilesystem:ClientMount",
          "elasticfilesystem:ClientWrite",
          "elasticfilesystem:DescribeFileSystems",
          "route53:GetHostedZone",
          "route53:ChangeResourceRecordSets",
          "route53:ListResourceRecordSets",
          "route53:ListHostedZones",
          "ecs:*",
          "ec2:DescribeNetworkInterfaces",
          "SNS:Publish"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecs_minecraft_task_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      },
    ]
  })

}

resource "aws_iam_role_policy" "ecs_minecraft_task_execution_policy" {
  name = "ecs_minecraft_task_execution_policy"
  role = aws_iam_role.ecs_task_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_ecs_task_definition" "minecraft_server" {
  family             = "minecraft_server"
  task_role_arn      = aws_iam_role.ecs_task_role.arn
  execution_role_arn = aws_iam_role.ecs_task_execution_role.arn
  container_definitions = templatefile("${path.module}/task-definitions/minecraft-server.json",
    {
      cluster_name = "minecraft-cluster",
      service_name = "minecraft-server",
      dns_zone     = var.dns_zone,
      server_name  = var.server_name,
      shutdown_min = var.shutdown_min,
      sns_topic    = aws_sns_topic.service_updates.arn
    }
  )


  requires_compatibilities = ["FARGATE"]

  cpu    = var.cpu
  memory = var.memory

  network_mode = "awsvpc"

  volume {
    name = "data"

    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.this.id
      root_directory     = "/minecraft"
      transit_encryption = "ENABLED"

      authorization_config {
        access_point_id = aws_efs_access_point.this.id
        iam             = "ENABLED"
      }
    }
  }
}

resource "aws_ecs_service" "minecraft_service" {
  name            = "minecraft-server"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.minecraft_server.id
  desired_count   = 0
  launch_type     = "FARGATE"

  network_configuration {
    subnets = flatten(["${var.subnet_ids}"])
    security_groups = [
      aws_security_group.backend.id
    ]
    assign_public_ip = true
  }

  lifecycle {
    ignore_changes = [desired_count]
  }
}

resource "aws_cloudwatch_log_group" "minecraft_server" {
  name              = "/ecs/minecraft_server"
  retention_in_days = 30
}


resource "aws_efs_file_system" "this" {
  creation_token = "minecraft"

  tags = {
    Name = "minecraft"
  }
}

resource "aws_efs_access_point" "this" {
  file_system_id = aws_efs_file_system.this.id

  posix_user {
    gid = 1000
    uid = 1000
  }

  root_directory {
    path = "/minecraft"
    creation_info {
      owner_gid   = 1000
      owner_uid   = 1000
      permissions = "0755"
    }
  }

}

resource "aws_efs_mount_target" "this" {
  for_each = toset(var.subnet_ids)

  file_system_id = aws_efs_file_system.this.id
  subnet_id      = each.key
  security_groups = [
    aws_security_group.backend.id
  ]
}

resource "aws_s3_bucket" "this" {
  bucket = "minecraft-files-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "minecraft files"
  }
}

resource "aws_s3_bucket_acl" "this" {
  bucket = aws_s3_bucket.this.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


resource "aws_security_group" "backend" {
  name        = "minecraft_backend"
  description = "minecraft service backend"
  vpc_id      = var.vpc_id

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "minecraft_backend"
  }
}


resource "aws_security_group_rule" "efs" {
  type              = "ingress"
  description       = "NFS from VPC"
  from_port         = 2049
  to_port           = 2049
  protocol          = "tcp"
  cidr_blocks       = var.subnet_cidr_blocks
  security_group_id = aws_security_group.backend.id
}


resource "aws_security_group_rule" "minecraft" {
  type              = "ingress"
  from_port         = 19132
  to_port           = 19132
  protocol          = "udp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.backend.id
}

resource "aws_datasync_location_s3" "this" {
  s3_bucket_arn = aws_s3_bucket.this.arn
  subdirectory  = "/minecraft"
  s3_config {
    bucket_access_role_arn = aws_iam_role.sync_execution_role.arn
  }
}

resource "aws_datasync_location_efs" "this" {
  efs_file_system_arn = aws_efs_file_system.this.arn

  subdirectory = "/minecraft"

  ec2_config {
    security_group_arns = [aws_security_group.backend.arn]
    subnet_arn          = var.sync_efs_subnet_arn
  }
}


resource "aws_iam_role" "sync_execution_role" {
  name = "data_sync_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "datasync.amazonaws.com"
        }
      },
    ]
  })

}

resource "aws_iam_role_policy" "sync_execution_policy" {
  name = "data_sync_policy"
  role = aws_iam_role.sync_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:*",
          "efs:*",
          "logs:*"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_sns_topic" "service_updates" {
  name = "minecraft-service-topic"
}


/*
resource "aws_datasync_task" "efs_to_s3" {
  destination_location_arn = aws_datasync_location_s3.this.arn
  name                     = "efs_to_s3"
  source_location_arn      = aws_datasync_location_efs.this.arn

  includes {
    filter_type = "SIMPLE_PATTERN"
    value       = "banned-ips.json|banned-players.json|ops.json|usercache.json|whitelist.json|server.properties|server-icon.png"
  }

  options {
    bytes_per_second = -1
  }
}

resource "aws_datasync_task" "s3_to_efs" {
  destination_location_arn = aws_datasync_location_efs.this.arn
  name                     = "s3_to_efs"
  source_location_arn      = aws_datasync_location_s3.this.arn

  includes {
    filter_type = "SIMPLE_PATTERN"
    value       = "banned-ips.json|banned-players.json|ops.json|usercache.json|whitelist.json|server.properties|server-icon.png"
  }

  options {
    bytes_per_second = -1
  }
}
*/