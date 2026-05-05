// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0
package botanist

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

	kubeapiserver "github.com/gardener/gardener/pkg/component/kubernetes/apiserver"
	"github.com/gardener/gardener/pkg/controllerutils"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
)

const clusterInfoRoleName = "kubeadm:bootstrap-signer-clusterinfo"

// PublishClusterInfo publishes the kube-public/cluster-info ConfigMap and the
// anonymous RBAC binding required for kubeadm-style discovery-token join
// (see https://kubernetes.io/docs/reference/access-authn-authz/bootstrap-tokens/).
// The bootstrap-signer controller in kube-controller-manager signs the
// ConfigMap automatically once a bootstrap token with usage-bootstrap-signing
// exists.
//
// TODO: cluster CA rotation is not handled here. The published kubeconfig is
// captured at init time. If the CA rotates day-2 (a gardenlet operation, not
// gardenadm init), the ConfigMap becomes stale and must be re-published by the
// gardenlet's reconciler — not gardenadm.
func (b *GardenadmBotanist) PublishClusterInfo(ctx context.Context) error {
	kubeconfig, err := b.buildClusterInfoKubeconfig()
	if err != nil {
		return fmt.Errorf("failed building cluster-info kubeconfig: %w", err)
	}

	c := b.SeedClientSet.Client()

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
		Name:      clusterInfoRoleName,
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
		Name:      clusterInfoRoleName,
		Namespace: metav1.NamespacePublic,
	}}
	if _, err := controllerutils.CreateOrGetAndMergePatch(ctx, c, rb, func() error {
		rb.RoleRef = rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     clusterInfoRoleName,
		}
		rb.Subjects = []rbacv1.Subject{{
			APIGroup: rbacv1.GroupName,
			Kind:     rbacv1.UserKind,
			Name:     "system:anonymous",
		}}
		return nil
	}); err != nil {
		return fmt.Errorf("failed reconciling cluster-info RoleBinding: %w", err)
	}

	b.Logger.Info("Published cluster-info for discovery-token join",
		"namespace", metav1.NamespacePublic, "configMap", bootstrapapi.ConfigMapClusterInfo)
	return nil
}

// buildClusterInfoKubeconfig returns a credential-less kubeconfig containing
// the cluster CA bundle and the API server endpoint. It reuses the admin
// kubeconfig produced earlier in the bootstrap flow as the source of truth
// and strips the user credentials.
func (b *GardenadmBotanist) buildClusterInfoKubeconfig() ([]byte, error) {
	adminKubeconfigSecret, ok := b.SecretsManager.Get(kubeapiserver.SecretNameUserKubeconfig)
	if !ok {
		return nil, fmt.Errorf("failed fetching secret %q", kubeapiserver.SecretNameUserKubeconfig)
	}

	cfg, err := clientcmd.Load(adminKubeconfigSecret.Data[secretsutils.DataKeyKubeconfig])
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
