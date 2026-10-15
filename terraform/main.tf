# ---------- VPC ----------
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# ---------- Public Subnets (for ALB + NAT) ----------
resource "aws_subnet" "public1" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.project_name}-public-1"
    Tier = "public"
  }
}

resource "aws_subnet" "public2" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.project_name}-public-2"
    Tier = "public"
  }
}

# ---------- Private Subnets (for ECS + EFS) ----------
resource "aws_subnet" "private1" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "${var.aws_region}a"
  tags = {
    Name = "${var.project_name}-private-1"
    Tier = "private"
  }
}

resource "aws_subnet" "private2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "${var.aws_region}b"
  tags = {
    Name = "${var.project_name}-private-2"
    Tier = "private"
  }
}

# ---------- Internet Gateway ----------
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.project_name}-igw"
  }
}

# ---------- Public Route Table ----------
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

resource "aws_route_table_association" "public1" {
  subnet_id      = aws_subnet.public1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public2" {
  subnet_id      = aws_subnet.public2.id
  route_table_id = aws_route_table.public.id
}

# ---------- Single NAT Gateway (cost-effective decision) ----------
resource "aws_eip" "nat" {
  domain = "vpc"
  tags = {
    Name = "${var.project_name}-nat-eip"
  }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public1.id
  tags = {
    Name = "${var.project_name}-nat"
  }
}

# ---------- Private Route Table (both private subnets share the single NAT) ----------
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  tags = {
    Name = "${var.project_name}-private-rt"
  }
}

resource "aws_route_table_association" "private1" {
  subnet_id      = aws_subnet.private1.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private2" {
  subnet_id      = aws_subnet.private2.id
  route_table_id = aws_route_table.private.id
}

# ---------- ALB Security Group ----------
resource "aws_security_group" "alb_sg" {
  name   = "${var.project_name}-alb-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # HTTP allowed only for redirect-to-HTTPS (added when we configure the listener)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-alb-sg" }
}

# ---------- ALB ----------
resource "aws_lb" "main" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public1.id, aws_subnet.public2.id]

  tags = { Name = "${var.project_name}-alb" }
}

# ---------- Target Group ----------
resource "aws_lb_target_group" "app" {
  name        = "${var.project_name}-tg"
  port        = 5000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    path                = "/api/health"
    matcher             = "200"
    healthy_threshold   = 2
    unhealthy_threshold = 5
    interval            = 30
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = "${var.project_name}-tg" }
}

# ---------- Listener (HTTP for now — HTTPS needs ACM cert, discuss separately) ----------
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
# ---------- ECR Repository ----------
resource "aws_ecr_repository" "app" {
  name                 = "${var.project_name}-backend"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = { Name = "${var.project_name}-backend" }
}

# ---------- ECS Security Group ----------
resource "aws_security_group" "ecs_sg" {
  name        = "${var.project_name}-ecs-sg"
  description = "Allow traffic from ALB to ECS"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5000
    to_port         = 5000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-ecs-sg" }
}

# ---------- ECS Cluster ----------
resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-cluster"
  tags = { Name = "${var.project_name}-cluster" }
}

# ---------- CloudWatch Log Group ----------
resource "aws_cloudwatch_log_group" "ecs_logs" {
  name              = "/ecs/${var.project_name}"
  retention_in_days = 30 # forensic tool — keep audit logs longer than default
}

# ---------- IAM Role: ECS Task Execution ----------
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "${var.project_name}-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
# ---------- EFS Security Group ----------
resource "aws_security_group" "efs_sg" {
  name        = "${var.project_name}-efs-sg"
  description = "Allow NFS traffic from ECS tasks only"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-efs-sg" }
}

# ---------- EFS File System ----------
resource "aws_efs_file_system" "persist" {
  creation_token = "${var.project_name}-persist"
  encrypted      = true # security-first: encryption at rest

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS" # cost-effective: infrequent-access tier for older files
  }

  tags = { Name = "${var.project_name}-persist" }
}

# ---------- EFS Mount Targets (one per private subnet) ----------
resource "aws_efs_mount_target" "private1" {
  file_system_id  = aws_efs_file_system.persist.id
  subnet_id       = aws_subnet.private1.id
  security_groups = [aws_security_group.efs_sg.id]
}

resource "aws_efs_mount_target" "private2" {
  file_system_id  = aws_efs_file_system.persist.id
  subnet_id       = aws_subnet.private2.id
  security_groups = [aws_security_group.efs_sg.id]
}
# ---------- Secrets Manager: OpenRouter API Key ----------
resource "aws_secretsmanager_secret" "openrouter_key" {
  name        = "${var.project_name}/openrouter-api-key"
  recovery_window_in_days = 0 
  description = "OpenRouter API key for EVI's LLM integration"
}

resource "aws_secretsmanager_secret_version" "openrouter_key" {
  secret_id     = aws_secretsmanager_secret.openrouter_key.id
  secret_string = var.openrouter_api_key
}

# ---------- Secrets Manager: Flask Secret Key ----------
resource "aws_secretsmanager_secret" "flask_secret_key" {
  name        = "${var.project_name}/flask-secret-key"
  recovery_window_in_days = 0 
  description = "Flask SECRET_KEY for session signing"
}

resource "aws_secretsmanager_secret_version" "flask_secret_key" {
  secret_id     = aws_secretsmanager_secret.flask_secret_key.id
  secret_string = var.flask_secret_key
}

# ---------- IAM Role: ECS Task Role (runtime permissions — EFS + Secrets access) ----------
resource "aws_iam_role" "ecs_task_role" {
  name = "${var.project_name}-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

# ---------- IAM Policy: allow reading only OUR secrets (least privilege) ----------
resource "aws_iam_role_policy" "secrets_access" {
  name = "${var.project_name}-secrets-access"
  role = aws_iam_role.ecs_task_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["secretsmanager:GetSecretValue"]
      Resource = [
        aws_secretsmanager_secret.openrouter_key.arn,
        aws_secretsmanager_secret.flask_secret_key.arn
      ]
    }]
  })
}

#TODO ---------- ECS Task Definition ----------
resource "aws_ecs_task_definition" "app" {
  family                   = "${var.project_name}-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  volume {
    name = "persist"
    efs_volume_configuration {
      file_system_id = aws_efs_file_system.persist.id
      root_directory = "/"
    }
  }

  container_definitions = jsonencode([{
    name      = "${var.project_name}-backend"
    image     = "${aws_ecr_repository.app.repository_url}:latest"
    essential = true

    portMappings = [{
      containerPort = 5000
      hostPort      = 5000
      protocol      = "tcp"
    }]

    mountPoints = [{
      sourceVolume  = "persist"
      containerPath = "/persist"
      readOnly      = false
    }]

    secrets = [
      { name = "OPENROUTER_API_KEY", valueFrom = aws_secretsmanager_secret.openrouter_key.arn },
      { name = "SECRET_KEY", valueFrom = aws_secretsmanager_secret.flask_secret_key.arn }
    ]

    environment = [
      { name = "LLM_OPENROUTER_MODEL", value = "openrouter/free" }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.ecs_logs.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])

  tags = { Name = "${var.project_name}-task" }
}

#TODO ---------- ECS Service ----------
resource "aws_ecs_service" "app" {
  name            = "${var.project_name}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.private1.id, aws_subnet.private2.id]
    security_groups  = [aws_security_group.ecs_sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "${var.project_name}-backend"
    container_port   = 5000
  }

  depends_on = [
    aws_iam_role_policy_attachment.ecs_execution_policy,
    aws_lb_listener.http
  ]

  tags = { Name = "${var.project_name}-service" }
}
