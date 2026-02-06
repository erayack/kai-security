#!/bin/bash
# Kai AWS Deployment Script
# Usage: ./deploy.sh [build|push|run|logs]

set -e

# Configuration - UPDATE THESE
export AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-}"
export AWS_REGION="${AWS_REGION:-us-east-1}"
export ECS_CLUSTER="${ECS_CLUSTER:-}"
export SUBNET_IDS="${SUBNET_IDS:-}"  # comma-separated
export SECURITY_GROUP="${SECURITY_GROUP:-}"

# Derived values
ECR_REPO="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/kai-security"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_config() {
    if [ -z "$AWS_ACCOUNT_ID" ]; then
        error "AWS_ACCOUNT_ID is not set. Export it or edit this script."
    fi
    if [ -z "$ECS_CLUSTER" ]; then
        error "ECS_CLUSTER is not set. Export it or edit this script."
    fi
}

cmd_build() {
    log "Building Docker image..."
    cd "$REPO_ROOT"
    docker build -f deploy/aws/Dockerfile -t kai-security:latest .
    log "Build complete!"
}

cmd_push() {
    check_config
    log "Authenticating with ECR..."
    aws ecr get-login-password --region $AWS_REGION | \
        docker login --username AWS --password-stdin $ECR_REPO

    log "Tagging image..."
    docker tag kai-security:latest $ECR_REPO:latest

    log "Pushing to ECR..."
    docker push $ECR_REPO:latest
    log "Push complete!"
}

cmd_run() {
    check_config

    if [ -z "$SUBNET_IDS" ] || [ -z "$SECURITY_GROUP" ]; then
        error "SUBNET_IDS and SECURITY_GROUP must be set"
    fi

    # Optional: override LIMIT
    LIMIT="${1:-2}"

    log "Running ECS task with LIMIT=$LIMIT..."

    TASK_ARN=$(aws ecs run-task \
        --cluster $ECS_CLUSTER \
        --task-definition kai-security-analysis \
        --launch-type FARGATE \
        --network-configuration "awsvpcConfiguration={subnets=[$SUBNET_IDS],securityGroups=[$SECURITY_GROUP],assignPublicIp=ENABLED}" \
        --overrides "{
            \"containerOverrides\": [{
                \"name\": \"kai-runner\",
                \"environment\": [
                    {\"name\": \"LIMIT\", \"value\": \"$LIMIT\"}
                ]
            }]
        }" \
        --region $AWS_REGION \
        --query 'tasks[0].taskArn' \
        --output text)

    log "Task started: $TASK_ARN"
    log "View logs: ./deploy.sh logs"
    echo ""
    echo "Or in AWS Console:"
    echo "https://$AWS_REGION.console.aws.amazon.com/cloudwatch/home?region=$AWS_REGION#logsV2:log-groups/log-group/\$252Fecs\$252Fkai-security-analysis"
}

cmd_logs() {
    log "Streaming CloudWatch logs (Ctrl+C to stop)..."
    aws logs tail /ecs/kai-security-analysis --follow --region $AWS_REGION
}

cmd_status() {
    check_config
    log "Checking running tasks..."
    aws ecs list-tasks \
        --cluster $ECS_CLUSTER \
        --family kai-security-analysis \
        --region $AWS_REGION
}

cmd_setup() {
    check_config
    log "Setting up AWS resources..."

    # Create ECR repo
    log "Creating ECR repository..."
    aws ecr create-repository --repository-name kai-security --region $AWS_REGION 2>/dev/null || \
        warn "ECR repository already exists"

    # Create log group
    log "Creating CloudWatch log group..."
    aws logs create-log-group --log-group-name /ecs/kai-security-analysis --region $AWS_REGION 2>/dev/null || \
        warn "Log group already exists"

    # Create task role
    log "Creating IAM task role..."
    aws iam create-role \
        --role-name kai-task-role \
        --assume-role-policy-document '{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }' 2>/dev/null || warn "Role already exists"

    aws iam put-role-policy \
        --role-name kai-task-role \
        --policy-name SecretsAccess \
        --policy-document '{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["secretsmanager:GetSecretValue"],
                "Resource": "arn:aws:secretsmanager:*:*:secret:kai/*"
            }]
        }' 2>/dev/null || warn "Policy already attached"

    log "Setup complete!"
    echo ""
    echo "Next steps:"
    echo "1. Create secrets in AWS Secrets Manager:"
    echo "   - kai/openrouter-api-key"
    echo "   - kai/mongo-uri (optional)"
    echo ""
    echo "2. Register task definition:"
    echo "   ./deploy.sh register"
    echo ""
    echo "3. Build and push image:"
    echo "   ./deploy.sh build"
    echo "   ./deploy.sh push"
}

cmd_register() {
    check_config
    log "Registering ECS task definition..."

    # Create simplified task definition (no EFS)
    cat > /tmp/kai-task-def.json << EOF
{
  "family": "kai-security-analysis",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "4096",
  "memory": "16384",
  "executionRoleArn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/kai-task-role",
  "containerDefinitions": [
    {
      "name": "kai-runner",
      "image": "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/kai-security:latest",
      "essential": true,
      "environment": [
        {"name": "LIMIT", "value": "2"},
        {"name": "MAIN_MODEL", "value": "anthropic/claude-opus-4.5"},
        {"name": "VERIFIER_MODEL", "value": "google/gemini-3-flash-preview"},
        {"name": "COMPILE_TIMEOUT", "value": "600"},
        {"name": "TEST_TIMEOUT", "value": "300"}
      ],
      "secrets": [
        {
          "name": "OPENROUTER_API_KEY",
          "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:kai/openrouter-api-key"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/kai-security-analysis",
          "awslogs-region": "${AWS_REGION}",
          "awslogs-stream-prefix": "kai"
        }
      }
    }
  ]
}
EOF

    aws ecs register-task-definition \
        --cli-input-json file:///tmp/kai-task-def.json \
        --region $AWS_REGION

    log "Task definition registered!"
}

cmd_help() {
    echo "Kai AWS Deployment Script"
    echo ""
    echo "Usage: ./deploy.sh <command> [args]"
    echo ""
    echo "Commands:"
    echo "  setup     - Create AWS resources (ECR, IAM, CloudWatch)"
    echo "  register  - Register ECS task definition"
    echo "  build     - Build Docker image locally"
    echo "  push      - Push image to ECR"
    echo "  run [N]   - Run ECS task (N = number of repos, default 2)"
    echo "  logs      - Stream CloudWatch logs"
    echo "  status    - Check running tasks"
    echo "  help      - Show this help"
    echo ""
    echo "Environment variables (set before running):"
    echo "  AWS_ACCOUNT_ID  - Your AWS account ID"
    echo "  AWS_REGION      - AWS region (default: us-east-1)"
    echo "  ECS_CLUSTER     - ECS cluster name"
    echo "  SUBNET_IDS      - Comma-separated subnet IDs"
    echo "  SECURITY_GROUP  - Security group ID"
    echo ""
    echo "Example:"
    echo "  export AWS_ACCOUNT_ID=123456789012"
    echo "  export ECS_CLUSTER=my-cluster"
    echo "  export SUBNET_IDS=subnet-abc,subnet-def"
    echo "  export SECURITY_GROUP=sg-xyz"
    echo "  ./deploy.sh setup"
    echo "  ./deploy.sh register"
    echo "  ./deploy.sh build && ./deploy.sh push"
    echo "  ./deploy.sh run 2"
}

# Main
case "${1:-help}" in
    setup)    cmd_setup ;;
    register) cmd_register ;;
    build)    cmd_build ;;
    push)     cmd_push ;;
    run)      cmd_run "$2" ;;
    logs)     cmd_logs ;;
    status)   cmd_status ;;
    help)     cmd_help ;;
    *)        error "Unknown command: $1. Run './deploy.sh help' for usage." ;;
esac
