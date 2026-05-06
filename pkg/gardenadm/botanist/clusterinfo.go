// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0
package botanist

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	bootstrapapi "k8s.io/cluster-bootstrap/token/api"

	kubeapiserver "github.com/gardener/gardener/pkg/component/kubernetes/apiserver"
	"github.com/gardener/gardener/pkg/utils/kubernetes/clusterinfo"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
)

// PublishClusterInfo publishes the kube-public/cluster-info ConfigMap and the
// anonymous RBAC binding required for kubeadm-style discovery-token join. The
// reusable logic lives in pkg/utils/kubernetes/clusterinfo; this wrapper just
// fetches the admin kubeconfig from the SecretsManager and strips its
// credentials before handing it to the helper.
//
// TODO: cluster CA rotation is not handled here. The published kubeconfig is
// captured at init time. If the CA rotates day-2 (a gardenlet operation, not
// gardenadm init), the ConfigMap becomes stale and must be re-published by the
// gardenlet's reconciler — not gardenadm.
func (b *GardenadmBotanist) PublishClusterInfo(ctx context.Context) error {
	adminKubeconfigSecret, ok := b.SecretsManager.Get(kubeapiserver.SecretNameUserKubeconfig)
	if !ok {
		return fmt.Errorf("failed fetching secret %q", kubeapiserver.SecretNameUserKubeconfig)
	}

	kubeconfig, err := clusterinfo.BuildKubeconfigFromAdmin(adminKubeconfigSecret.Data[secretsutils.DataKeyKubeconfig])
	if err != nil {
		return fmt.Errorf("failed building cluster-info kubeconfig: %w", err)
	}

	if err := clusterinfo.Publish(ctx, b.SeedClientSet.Client(), kubeconfig); err != nil {
		return err
	}

	b.Logger.Info("Published cluster-info for discovery-token join",
		"namespace", metav1.NamespacePublic, "configMap", bootstrapapi.ConfigMapClusterInfo)
	return nil
}
