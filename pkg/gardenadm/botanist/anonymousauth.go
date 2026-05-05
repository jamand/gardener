// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package botanist

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/component/kubernetes/apiserver"
	"github.com/gardener/gardener/pkg/gardenadm"
)

// AnonymousAuthConfigMapName is the name of the ConfigMap holding the structured
// AuthenticationConfiguration that path-scopes anonymous access for self-hosted shoots
// to exactly the endpoints required for kubeadm-style discovery via `gardenadm join`.
const AnonymousAuthConfigMapName = "gardenadm-anonymous-auth"

// anonymousAuthConfigYAML enables anonymous authentication only on the paths necessary
// for the discovery flow: the standard health endpoints and the kube-public/cluster-info
// ConfigMap. Anything else is rejected at authentication time, regardless of RBAC.
//
// This relies on the AnonymousAuthConfigurableEndpoints feature gate, which is GA in
// Kubernetes 1.34+ and on by default in 1.31+.
const anonymousAuthConfigYAML = `apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
anonymous:
  enabled: true
  conditions:
  - path: /healthz
  - path: /livez
  - path: /readyz
  - path: /api/v1/namespaces/kube-public/configmaps/cluster-info
`

// injectAnonymousAuthConfig wires up a structured AuthenticationConfiguration that
// path-scopes anonymous access for the self-hosted shoot. It appends a ConfigMap to the
// resources slice (so initializeFakeGardenResources creates it on the fake garden client,
// where shared.computeAPIServerAuthenticationConfig will fetch it) and points the Shoot's
// StructuredAuthentication at that ConfigMap.
//
// If the operator already configured StructuredAuthentication on the Shoot manifest,
// their setting is preserved.
func injectAnonymousAuthConfig(resources *gardenadm.Resources) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      AnonymousAuthConfigMapName,
			Namespace: resources.Shoot.Namespace,
		},
		Data: map[string]string{apiserver.DataKeyConfigMapAuthenticationConfig: anonymousAuthConfigYAML},
	}
	resources.ConfigMaps = append(resources.ConfigMaps, cm)

	if resources.Shoot.Spec.Kubernetes.KubeAPIServer == nil {
		resources.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{}
	}
	if resources.Shoot.Spec.Kubernetes.KubeAPIServer.StructuredAuthentication == nil {
		resources.Shoot.Spec.Kubernetes.KubeAPIServer.StructuredAuthentication = &gardencorev1beta1.StructuredAuthentication{
			ConfigMapName: AnonymousAuthConfigMapName,
		}
	}
}
