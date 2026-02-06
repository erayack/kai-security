# Kai AWS Setup - Team Checklist

**Send this to your DevOps/Platform team**

---

## What We Need

We need to run a long-running (6-12 hours) containerized job for security analysis. The job needs:
- 4 vCPU, 16GB RAM
- Outbound internet access (HTTPS to OpenRouter API)
- Access to secrets in AWS Secrets Manager
- CloudWatch logging

## Resources to Create

### 1. ECR Repository
```bash
aws ecr create-repository --repository-name kai-security --region <REGION>
```

### 2. Secrets in AWS Secrets Manager

| Secret Name | Description |
|-------------|-------------|
| `kai/openrouter-api-key` | OpenRouter API key (I'll provide the value) |
| `kai/mongo-uri` | MongoDB connection string (optional, I'll provide) |

```bash
# Example (I'll provide actual values)
aws secretsmanager create-secret \
  --name kai/openrouter-api-key \
  --secret-string "sk-or-v1-xxx" \
  --region <REGION>
```

### 3. IAM Role: `kai-task-role`

Trust policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
```

Permissions policy (inline):
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["secretsmanager:GetSecretValue"],
    "Resource": "arn:aws:secretsmanager:*:*:secret:kai/*"
  }]
}
```

### 4. CloudWatch Log Group
```bash
aws logs create-log-group --log-group-name /ecs/kai-security-analysis --region <REGION>
```

### 5. Network Configuration

I need:
- **Subnet IDs** (public subnets with internet access, or private with NAT)
- **Security Group ID** (must allow outbound HTTPS/443)

---

## Information I Need Back

Please provide:

| Item | Value |
|------|-------|
| AWS Account ID | |
| AWS Region | |
| ECS Cluster Name | |
| Subnet IDs (comma-separated) | |
| Security Group ID | |
| Confirm: ECR repo created? | [ ] Yes |
| Confirm: Secrets created? | [ ] Yes |
| Confirm: IAM role created? | [ ] Yes |
| Confirm: Log group created? | [ ] Yes |

---

## Quick Setup Commands (for team)

```bash
# Set variables
export AWS_ACCOUNT_ID=123456789012
export AWS_REGION=us-east-1

# 1. Create ECR repo
aws ecr create-repository --repository-name kai-security --region $AWS_REGION

# 2. Create log group
aws logs create-log-group --log-group-name /ecs/kai-security-analysis --region $AWS_REGION

# 3. Create IAM role
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

# 4. Create secrets (I'll provide actual values)
aws secretsmanager create-secret \
  --name kai/openrouter-api-key \
  --secret-string "PLACEHOLDER" \
  --region $AWS_REGION
```

---

## Notes

- The job runs for 6-12 hours per repository
- We'll run 2-3 repos at a time initially
- No GPU required, just CPU
- Estimated cost: ~$0.20/hour ($2-3 per run)
- The container is stateless; results go to logs and optional MongoDB
