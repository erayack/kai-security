# Kai AWS Deployment Guide

This guide walks through deploying Kai on AWS for reliable, long-running security analysis jobs.

## Overview

**Why AWS over Modal?**
- No preemption - On-demand instances are guaranteed
- Full control over resources
- Better for long-running jobs (10+ hours)
- ECS Fargate = serverless containers with no interruptions

**Resources needed:**
- 4 vCPU, 16GB RAM minimum
- ~$0.20/hour for Fargate
- ~$0.17/hour for EC2 (c5.xlarge)

---

## Option 1: ECS Fargate (Recommended)

### Prerequisites (Ask your team to set up)

1. **ECR Repository** for Docker images
2. **ECS Cluster** (you likely already have one)
3. **Secrets in AWS Secrets Manager:**
   - `kai/openrouter-api-key` - Your OpenRouter API key
   - `kai/mongo-uri` - MongoDB connection string (optional)
4. **IAM Roles:**
   - `ecsTaskExecutionRole` (standard, likely exists)
   - `kai-task-role` (for Secrets Manager access)
5. **CloudWatch Log Group:** `/ecs/kai-security-analysis`
6. **VPC with public subnets** (for internet access to APIs)

### Step 1: Build and Push Docker Image

```bash
# Set your AWS account details
export AWS_ACCOUNT_ID=123456789012
export AWS_REGION=us-east-1

# Authenticate Docker to ECR
aws ecr get-login-password --region $AWS_REGION | \
  docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

# Create ECR repository (one-time)
aws ecr create-repository --repository-name kai-security --region $AWS_REGION

# Build the image (from repo root)
cd /path/to/exploit-agent
docker build -f deploy/aws/Dockerfile -t kai-security:latest .

# Tag and push
docker tag kai-security:latest $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/kai-security:latest
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/kai-security:latest
```

### Step 2: Create Secrets in AWS Secrets Manager

```bash
# Create OpenRouter API key secret
aws secretsmanager create-secret \
  --name kai/openrouter-api-key \
  --secret-string "sk-or-v1-your-api-key-here" \
  --region $AWS_REGION

# Create MongoDB URI secret (optional)
aws secretsmanager create-secret \
  --name kai/mongo-uri \
  --secret-string "mongodb+srv://user:pass@cluster.mongodb.net/kai_batch" \
  --region $AWS_REGION
```

### Step 3: Create IAM Role for Task

```bash
# Create the task role (allows reading secrets)
aws iam create-role \
  --role-name kai-task-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ecs-tasks.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach secrets access policy
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
  }'
```

### Step 4: Create CloudWatch Log Group

```bash
aws logs create-log-group \
  --log-group-name /ecs/kai-security-analysis \
  --region $AWS_REGION
```

### Step 5: Register Task Definition

```bash
# Replace placeholders in task definition
export AWS_ACCOUNT_ID=123456789012
export AWS_REGION=us-east-1

# Create task definition (remove EFS volume if not using)
cat deploy/aws/ecs-task-definition.json | \
  sed "s/\${AWS_ACCOUNT_ID}/$AWS_ACCOUNT_ID/g" | \
  sed "s/\${AWS_REGION}/$AWS_REGION/g" | \
  sed '/"volumes"/,/^  ]/d' | \
  sed '/"mountPoints"/,/]/d' > /tmp/task-def.json

aws ecs register-task-definition \
  --cli-input-json file:///tmp/task-def.json \
  --region $AWS_REGION
```

### Step 6: Run the Task

```bash
# Get your VPC subnet IDs (public subnets with internet access)
SUBNET_IDS="subnet-xxxxx,subnet-yyyyy"
SECURITY_GROUP="sg-xxxxx"  # Must allow outbound HTTPS

# Run the task
aws ecs run-task \
  --cluster your-cluster-name \
  --task-definition kai-security-analysis \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[$SUBNET_IDS],securityGroups=[$SECURITY_GROUP],assignPublicIp=ENABLED}" \
  --overrides '{
    "containerOverrides": [{
      "name": "kai-runner",
      "environment": [
        {"name": "LIMIT", "value": "2"}
      ]
    }]
  }' \
  --region $AWS_REGION
```

### Step 7: Monitor the Task

```bash
# Watch logs in real-time
aws logs tail /ecs/kai-security-analysis --follow --region $AWS_REGION

# Or view in AWS Console:
# CloudWatch > Log Groups > /ecs/kai-security-analysis
```

---

## Option 2: EC2 (Simpler, Good for Testing)

### Step 1: Launch EC2 Instance

```bash
# Launch a c5.xlarge (4 vCPU, 8GB) or c5.2xlarge (8 vCPU, 16GB)
aws ec2 run-instances \
  --image-id ami-0c7217cdde317cfec \  # Ubuntu 22.04 in us-east-1
  --instance-type c5.2xlarge \
  --key-name your-key-pair \
  --security-group-ids sg-xxxxx \
  --subnet-id subnet-xxxxx \
  --associate-public-ip-address \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":100}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=kai-runner}]' \
  --region us-east-1
```

### Step 2: SSH and Setup

```bash
# SSH to instance
ssh -i your-key.pem ubuntu@<instance-public-ip>

# Install dependencies
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv python3-pip git curl

# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc
foundryup

# Clone repo
git clone https://github.com/your-org/exploit-agent.git
cd exploit-agent

# Create venv and install
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .

# Set environment variables
export OPENROUTER_API_KEY="sk-or-v1-your-key"
export MONGO_URI="mongodb+srv://..."  # optional
```

### Step 3: Run with tmux (Survives SSH Disconnect)

```bash
# Start tmux session
tmux new -s kai

# Run the analysis
python scripts/batch_cantina_runner.py \
  --limit 2 \
  --main-model anthropic/claude-opus-4.5 \
  --compile-timeout 600 \
  --save-to-db

# Detach: Ctrl+B, then D
# Reattach later: tmux attach -t kai
```

### Step 4: Monitor

```bash
# Reattach to see live output
tmux attach -t kai

# Or tail the output directory
tail -f output/cantina_batch/*/consolidated_report.md
```

---

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENROUTER_API_KEY` | Yes | OpenRouter API key for LLM access |
| `MONGO_URI` | No | MongoDB connection string for persistence |
| `LIMIT` | No | Number of repos to analyze (default: all 17) |
| `MAIN_MODEL` | No | Primary model (default: `anthropic/claude-opus-4.5`) |
| `VERIFIER_MODEL` | No | Verifier model (default: `google/gemini-3-flash-preview`) |
| `COMPILE_TIMEOUT` | No | Compilation timeout in seconds (default: 600) |
| `TEST_TIMEOUT` | No | Test timeout in seconds (default: 300) |

---

## Cost Estimates

| Resource | Specs | Hourly Cost | For 10-hour run |
|----------|-------|-------------|-----------------|
| ECS Fargate | 4 vCPU, 16GB | ~$0.20/hr | ~$2.00 |
| EC2 c5.xlarge | 4 vCPU, 8GB | ~$0.17/hr | ~$1.70 |
| EC2 c5.2xlarge | 8 vCPU, 16GB | ~$0.34/hr | ~$3.40 |

Plus LLM API costs (~$10-20 per repo depending on models).

---

## Troubleshooting

### Task exits immediately
- Check CloudWatch logs for errors
- Verify secrets are correctly set up
- Ensure security group allows outbound HTTPS (port 443)

### Out of memory
- Increase memory in task definition (up to 30GB on Fargate)
- Use EC2 with more RAM

### Task runs forever
- Check CloudWatch logs for stuck state
- Individual repos can take 6-12 hours
- Set a deadline using ECS stop timeout

### Can't pull image
- Verify ECR repository exists
- Check IAM permissions for ecsTaskExecutionRole
- Ensure image was pushed successfully

---

## Quick Start Checklist

For your team to set up:

- [ ] Create ECR repository: `kai-security`
- [ ] Create Secrets Manager secrets:
  - [ ] `kai/openrouter-api-key`
  - [ ] `kai/mongo-uri` (optional)
- [ ] Create IAM role: `kai-task-role` with Secrets Manager access
- [ ] Create CloudWatch log group: `/ecs/kai-security-analysis`
- [ ] Identify VPC subnets and security group for the task
- [ ] Provide you with:
  - AWS Account ID
  - AWS Region
  - ECS Cluster name
  - Subnet IDs (comma-separated)
  - Security Group ID

Once they provide these, you can build/push the image and run tasks!
