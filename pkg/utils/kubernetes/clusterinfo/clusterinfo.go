// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// Package clusterinfo publishes the kube-public/cluster-info ConfigMap and the
// anonymous RBAC binding required for kubeadm-style discovery-token join.
// See https://kubernetes.io/docs/reference/access-authn-authz/bootstrap-tokens/.
package clusterinfo

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdlatest "k8s.io/client-go/tools/clientcmd/api/latest"
	bootstrapapi "k8s.io/cluster-bootstrap/token/api"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener/pkg/controllerutils"
)

// RoleName is the name of the Role and RoleBinding granting anonymous read
// access to the kube-public/cluster-info ConfigMap. The name matches kubeadm's.
const RoleName = "kubeadm:bootstrap-signer-clusterinfo"

// Publish reconciles the kube-public/cluster-info ConfigMap with the supplied
// kubeconfig payload, and the Role/RoleBinding granting anonymous read access
// to it. The bootstrap-signer controller in kube-controller-manager signs the
// ConfigMap automatically once a bootstrap token with usage-bootstrap-signing
// exists. Foreign annotations on the ConfigMap (e.g. the JWS signatures
// written by bootstrap-signer) are preserved across reconciliations.
func Publish(ctx context.Context, c client.Client, kubeconfig []byte) error {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name:      bootstrapapi.ConfigMapClusterInfo,
		Namespace: metav1.NamespacePublic,
	}}
	if _, err := controllerutils.CreateOrGetAndMergePatch(ctx, c, cm, func() error {
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		cm.Data[bootstrapapi.KubeConfigKey] = string(kubeconfig)
		return nil
	}); err != nil {
		return fmt.Errorf("failed reconciling cluster-info ConfigMap: %w", err)
	}

	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{
		Name:      RoleName,
		Namespace: metav1.NamespacePublic,
	}}
	if _, err := controllerutils.CreateOrGetAndMergePatch(ctx, c, role, func() error {
		role.Rules = []rbacv1.PolicyRule{{
			APIGroups:     []string{""},
			Resources:     []string{"configmaps"},
			ResourceNames: []string{bootstrapapi.ConfigMapClusterInfo},
			Verbs:         []string{"get"},
		}}
		return nil
	}); err != nil {
		return fmt.Errorf("failed reconciling cluster-info Role: %w", err)
	}

	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{
		Name:      RoleName,
		Namespace: metav1.NamespacePublic,
	}}
	if _, err := controllerutils.CreateOrGetAndMergePatch(ctx, c, rb, func() error {
		rb.RoleRef = rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     RoleName,
		}
		rb.Subjects = []rbacv1.Subject{{
			APIGroup: rbacv1.GroupName,
			Kind:     rbacv1.GroupKind,
			Name:     "system:unauthenticated",
		}}
		return nil
	}); err != nil {
		return fmt.Errorf("failed reconciling cluster-info RoleBinding: %w", err)
	}

	return nil
}

// BuildKubeconfigFromAdmin returns a credential-less kubeconfig suitable for
// publication via Publish: it strips user credentials, contexts, and the
// current-context from the supplied admin kubeconfig, leaving only the
// cluster CA bundle and API server endpoint.
//
// The result is intentionally not directly usable with `kubectl --kubeconfig`
// (the caller would need to pass --cluster) — the file is consumed by
// kubeadm-style discovery, not as a normal kubeconfig. Stripping the context
// avoids leaking the admin user name into the public ConfigMap.
func BuildKubeconfigFromAdmin(adminKubeconfig []byte) ([]byte, error) {
	cfg, err := clientcmd.Load(adminKubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed parsing admin kubeconfig: %w", err)
	}

	cfg.AuthInfos = nil
	cfg.Contexts = nil
	cfg.CurrentContext = ""

	out, err := runtime.Encode(clientcmdlatest.Codec, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed serializing cluster-info kubeconfig: %w", err)
	}
	return out, nil
}
