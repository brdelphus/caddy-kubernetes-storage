# caddy-kubernetes-storage

A [Caddy v2](https://caddyserver.com) storage backend that keeps TLS certificates, keys, and ACME account data in **Kubernetes Secrets**.

Designed for Caddy running as a DaemonSet or multi-replica Deployment where multiple pods share the same ACME state. Each certmagic key maps to one Secret; distributed locking is handled via Kubernetes' optimistic concurrency (resource-version conflict detection) without any external dependencies.

> Upgraded from [`PalmStoneGames/caddy-kubernetes-storage`](https://github.com/PalmStoneGames/caddy-kubernetes-storage) (Caddy v1) to Caddy v2 / certmagic with modern `k8s.io/client-go`.

---

## Install

```bash
xcaddy build \
  --with github.com/brdelphus/caddy-kubernetes-storage
```

---

## Configuration

### JSON

```json
{
  "storage": {
    "module": "kubernetes",
    "namespace": "caddy"
  }
}
```

### Caddyfile

```
storage kubernetes {
    namespace caddy
}
```

| Option | Default | Description |
|---|---|---|
| `namespace` | Pod's own namespace | Kubernetes namespace to create Secrets in |
| `kubeconfig` | *(in-cluster)* | Path to kubeconfig file (for out-of-cluster use) |

---

## RBAC

The Caddy pod's ServiceAccount needs the following permissions in the target namespace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: caddy-storage
  namespace: caddy
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get, list, watch, create, update, delete]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: caddy-storage
  namespace: caddy
subjects:
  - kind: ServiceAccount
    name: caddy
    namespace: caddy
roleRef:
  kind: Role
  name: caddy-storage
  apiGroup: rbac.authorization.k8s.io
```

---

## How it works

| certmagic operation | Kubernetes action |
|---|---|
| `Store(key, value)` | Create or update a Secret named `caddy-tls-<sanitized-key>` |
| `Load(key)` | Get the Secret; return `data["value"]` |
| `Delete(key)` | Delete the Secret |
| `Exists(key)` | Get the Secret; return `true` on 200 |
| `List(prefix, recursive)` | List Secrets with label `caddy.storage/managed=true`; filter by annotation |
| `Stat(key)` | Get the Secret; return size + creation timestamp |
| `Lock(name)` | Create a `caddy-lock-<name>` Secret; retry until created; auto-expire after 5 min |
| `Unlock(name)` | Delete the lock Secret |

Secrets are labelled `caddy.storage/managed=true` and annotated with the original certmagic key so List operations can recover the full key path.

---

## License

MIT
