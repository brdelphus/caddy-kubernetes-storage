// Package k8sstorage implements a Caddy v2 storage backend that keeps TLS
// assets (certificates, keys, ACME accounts) in Kubernetes Secrets.
//
// Each certmagic key maps to one Secret in the configured namespace.
// Distributed locking uses optimistic concurrency via Kubernetes' built-in
// resource-version conflict detection.
package k8sstorage

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func init() {
	caddy.RegisterModule(&Storage{})
}

const (
	labelManaged     = "caddy.storage/managed"
	annotationKey    = "caddy.storage/key"
	secretPrefix     = "caddy-tls-"
	lockPrefix       = "caddy-lock-"
	lockTimeout      = 5 * time.Minute
	lockPollInterval = 500 * time.Millisecond
)

// Storage is a Caddy storage module backed by Kubernetes Secrets.
//
// JSON config:
//
//	"storage": {
//	    "module": "kubernetes",
//	    "namespace": "caddy"
//	}
//
// Caddyfile config:
//
//	storage kubernetes {
//	    namespace caddy
//	}
type Storage struct {
	// Kubernetes namespace to store Secrets in.
	// Defaults to the namespace of the running pod (via the service-account mount).
	Namespace string `json:"namespace,omitempty"`

	// Path to a kubeconfig file. Omit to use in-cluster config (recommended for pods).
	Kubeconfig string `json:"kubeconfig,omitempty"`

	client *kubernetes.Clientset
	ns     string
}

// CaddyModule returns module metadata.
func (*Storage) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.storage.kubernetes",
		New: func() caddy.Module { return new(Storage) },
	}
}

// Provision creates the Kubernetes client.
func (s *Storage) Provision(_ caddy.Context) error {
	s.ns = s.Namespace
	if s.ns == "" {
		s.ns = podNamespace()
	}

	var (
		cfg *rest.Config
		err error
	)
	if s.Kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", s.Kubeconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return fmt.Errorf("kubernetes storage: build config: %w", err)
	}

	s.client, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("kubernetes storage: create client: %w", err)
	}
	return nil
}

// CertMagicStorage implements caddy.StorageConverter.
func (s *Storage) CertMagicStorage() (certmagic.Storage, error) { return s, nil }

// Store saves value at key as a Kubernetes Secret.
func (s *Storage) Store(ctx context.Context, key string, value []byte) error {
	name := secretName(key)

	existing, err := s.client.CoreV1().Secrets(s.ns).Get(ctx, name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		_, err = s.client.CoreV1().Secrets(s.ns).Create(ctx, s.newSecret(name, key, value), metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	existing.Data = map[string][]byte{"value": value}
	if existing.Annotations == nil {
		existing.Annotations = make(map[string]string)
	}
	existing.Annotations[annotationKey] = key
	_, err = s.client.CoreV1().Secrets(s.ns).Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

// Load retrieves the value at key.
func (s *Storage) Load(ctx context.Context, key string) ([]byte, error) {
	secret, err := s.client.CoreV1().Secrets(s.ns).Get(ctx, secretName(key), metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return nil, fs.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	return secret.Data["value"], nil
}

// Delete removes the secret at key.
func (s *Storage) Delete(ctx context.Context, key string) error {
	err := s.client.CoreV1().Secrets(s.ns).Delete(ctx, secretName(key), metav1.DeleteOptions{})
	if k8serrors.IsNotFound(err) {
		return nil
	}
	return err
}

// Exists returns true if the key exists.
func (s *Storage) Exists(ctx context.Context, key string) bool {
	_, err := s.client.CoreV1().Secrets(s.ns).Get(ctx, secretName(key), metav1.GetOptions{})
	return err == nil
}

// List returns all keys with the given prefix.
// When recursive is false only immediate children are returned; deeper paths
// are collapsed to their first path segment below the prefix.
func (s *Storage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	secrets, err := s.client.CoreV1().Secrets(s.ns).List(ctx, metav1.ListOptions{
		LabelSelector: labelManaged + "=true",
	})
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var keys []string

	for _, secret := range secrets.Items {
		k, ok := secret.Annotations[annotationKey]
		if !ok || !strings.HasPrefix(k, prefix) {
			continue
		}
		if recursive {
			keys = append(keys, k)
			continue
		}
		// Non-recursive: collapse to immediate child.
		rel := strings.TrimPrefix(strings.TrimPrefix(k, prefix), "/")
		if idx := strings.Index(rel, "/"); idx >= 0 {
			child := strings.TrimRight(prefix, "/") + "/" + rel[:idx]
			if _, exists := seen[child]; !exists {
				seen[child] = struct{}{}
				keys = append(keys, child)
			}
		} else {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// Stat returns metadata about key.
func (s *Storage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	secret, err := s.client.CoreV1().Secrets(s.ns).Get(ctx, secretName(key), metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return certmagic.KeyInfo{}, fs.ErrNotExist
	}
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	return certmagic.KeyInfo{
		Key:        key,
		Modified:   secret.CreationTimestamp.Time,
		Size:       int64(len(secret.Data["value"])),
		IsTerminal: true,
	}, nil
}

// Lock acquires a distributed lock for name, blocking until it is available.
// The lock is automatically released after lockTimeout to prevent deadlocks.
func (s *Storage) Lock(ctx context.Context, name string) error {
	lockName := lockSecretName(name)

	for {
		expiry := time.Now().Add(lockTimeout).UTC().Format(time.RFC3339)
		lockSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:        lockName,
				Namespace:   s.ns,
				Labels:      map[string]string{labelManaged: "true"},
				Annotations: map[string]string{"caddy.storage/lock-expiry": expiry},
			},
		}
		_, err := s.client.CoreV1().Secrets(s.ns).Create(ctx, lockSecret, metav1.CreateOptions{})
		if err == nil {
			return nil // acquired
		}
		if !k8serrors.IsAlreadyExists(err) {
			return err
		}

		// Lock exists — check if it has expired.
		existing, err := s.client.CoreV1().Secrets(s.ns).Get(ctx, lockName, metav1.GetOptions{})
		if k8serrors.IsNotFound(err) {
			continue // deleted between Create and Get; retry immediately
		}
		if err != nil {
			return err
		}

		if exp, parseErr := time.Parse(time.RFC3339, existing.Annotations["caddy.storage/lock-expiry"]); parseErr == nil && time.Now().After(exp) {
			_ = s.client.CoreV1().Secrets(s.ns).Delete(ctx, lockName, metav1.DeleteOptions{})
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(lockPollInterval):
		}
	}
}

// Unlock releases the distributed lock for name.
func (s *Storage) Unlock(ctx context.Context, name string) error {
	err := s.client.CoreV1().Secrets(s.ns).Delete(ctx, lockSecretName(name), metav1.DeleteOptions{})
	if k8serrors.IsNotFound(err) {
		return nil
	}
	return err
}

// UnmarshalCaddyfile parses Caddyfile storage block:
//
//	storage kubernetes {
//	    namespace <ns>
//	    kubeconfig <path>
//	}
func (s *Storage) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "namespace":
				if !d.NextArg() {
					return d.ArgErr()
				}
				s.Namespace = d.Val()
			case "kubeconfig":
				if !d.NextArg() {
					return d.ArgErr()
				}
				s.Kubeconfig = d.Val()
			default:
				return d.Errf("unrecognised option: %s", d.Val())
			}
		}
	}
	return nil
}

func (s *Storage) newSecret(name, key string, value []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   s.ns,
			Labels:      map[string]string{labelManaged: "true"},
			Annotations: map[string]string{annotationKey: key},
		},
		Data: map[string][]byte{"value": value},
	}
}

// secretName maps a certmagic key to a valid Kubernetes Secret name.
// Names must be ≤253 characters, lowercase alphanumeric and '-'.
func secretName(key string) string {
	return clampName(secretPrefix, key)
}

func lockSecretName(name string) string {
	return clampName(lockPrefix, name)
}

func clampName(prefix, key string) string {
	name := prefix + sanitize(key)
	if len(name) <= 253 {
		return name
	}
	h := sha256.Sum256([]byte(key))
	suffix := fmt.Sprintf("-%x", h[:8])
	return name[:253-len(suffix)] + suffix
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func podNamespace() string {
	data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return "default"
	}
	return strings.TrimSpace(string(data))
}

// Compile-time interface assertions.
var (
	_ certmagic.Storage      = (*Storage)(nil)
	_ caddy.StorageConverter = (*Storage)(nil)
	_ caddy.Provisioner      = (*Storage)(nil)
	_ caddyfile.Unmarshaler  = (*Storage)(nil)
)
