// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package botanist

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/component/kubernetes/apiserver"
	"github.com/gardener/gardener/pkg/gardenadm"
)

// AnonymousAuthConfigMapName is the name of the ConfigMap holding the structured
// AuthenticationConfiguration that path-scopes anonymous access for self-hosted shoots
// to exactly the endpoints required for kubeadm-style discovery via `gardenadm join`.
const AnonymousAuthConfigMapName = "gardenadm-anonymous-auth"

// anonymousAuthDiscoveryPaths are the request paths on which anonymous access must be
// enabled for the kubeadm-style discovery flow to function — currently just the
// cluster-info ConfigMap fetch.
//
// This relies on the AnonymousAuthConfigurableEndpoints feature gate, GA in Kubernetes
// 1.34+ and on by default in 1.31+.
var anonymousAuthDiscoveryPaths = []string{
	"/api/v1/namespaces/kube-public/configmaps/cluster-info",
}

// injectAnonymousAuthConfig wires up a structured AuthenticationConfiguration that
// path-scopes anonymous access for the self-hosted shoot, so that `gardenadm join`
// can fetch the kube-public/cluster-info ConfigMap unauthenticated.
//
// Two cases:
//
//   - The operator did not configure StructuredAuthentication: a default ConfigMap is
//     appended to resources.ConfigMaps and the Shoot's StructuredAuthentication is set
//     to point at it.
//   - The operator already configured StructuredAuthentication: their reference is
//     preserved; the referenced ConfigMap (which must be present in resources.ConfigMaps)
//     is merged in-place to additionally enable anonymous access on the discovery paths.
//
// Returns an error if the operator referenced a ConfigMap that is not loaded into
// resources.ConfigMaps, or if their config cannot be parsed.
func injectAnonymousAuthConfig(resources *gardenadm.Resources) error {
	if resources.Shoot.Spec.Kubernetes.KubeAPIServer == nil {
		resources.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{}
	}

	if existing := resources.Shoot.Spec.Kubernetes.KubeAPIServer.StructuredAuthentication; existing != nil {
		return mergeDiscoveryPathsIntoExistingConfigMap(resources, existing.ConfigMapName)
	}

	encoded, err := encodeAnonymousAuthDiscoveryConfig()
	if err != nil {
		return err
	}

	resources.Shoot.Spec.Kubernetes.KubeAPIServer.StructuredAuthentication = &gardencorev1beta1.StructuredAuthentication{
		ConfigMapName: AnonymousAuthConfigMapName,
	}
	resources.ConfigMaps = append(resources.ConfigMaps, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      AnonymousAuthConfigMapName,
			Namespace: resources.Shoot.Namespace,
		},
		Data: map[string]string{apiserver.DataKeyConfigMapAuthenticationConfig: string(encoded)},
	})
	return nil
}

// encodeAnonymousAuthDiscoveryConfig builds the default AuthenticationConfiguration
// that enables anonymous access on the discovery paths only.
func encodeAnonymousAuthDiscoveryConfig() ([]byte, error) {
	cfg := &apiserverv1beta1.AuthenticationConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiserverv1beta1.ConfigSchemeGroupVersion.String(),
			Kind:       "AuthenticationConfiguration",
		},
		Anonymous: &apiserverv1beta1.AnonymousAuthConfig{Enabled: true},
	}
	for _, p := range anonymousAuthDiscoveryPaths {
		cfg.Anonymous.Conditions = append(cfg.Anonymous.Conditions, apiserverv1beta1.AnonymousAuthCondition{Path: p})
	}

	out, err := runtime.Encode(apiserver.ConfigCodec, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed encoding default AuthenticationConfiguration: %w", err)
	}
	return out, nil
}

// mergeDiscoveryPathsIntoExistingConfigMap finds the operator-supplied AuthenticationConfiguration
// ConfigMap by name in resources.ConfigMaps and ensures the discovery paths are present in
// anonymous.conditions. If anonymous is unset, it is initialized; if it is enabled with no path
// conditions (i.e. anonymous everywhere), nothing is changed.
func mergeDiscoveryPathsIntoExistingConfigMap(resources *gardenadm.Resources, name string) error {
	var cm *corev1.ConfigMap
	for _, candidate := range resources.ConfigMaps {
		if candidate.Name == name && candidate.Namespace == resources.Shoot.Namespace {
			cm = candidate
			break
		}
	}
	if cm == nil {
		return fmt.Errorf("the Shoot references AuthenticationConfiguration ConfigMap %q via spec.kubernetes.kubeAPIServer.structuredAuthentication, but it is not loaded from the manifests directory; either include it or unset the reference so gardenadm can manage it", name)
	}

	raw, ok := cm.Data[apiserver.DataKeyConfigMapAuthenticationConfig]
	if !ok {
		return fmt.Errorf("AuthenticationConfiguration ConfigMap %q is missing the %q data key", name, apiserver.DataKeyConfigMapAuthenticationConfig)
	}

	cfg := &apiserverv1beta1.AuthenticationConfiguration{}
	if err := runtime.DecodeInto(apiserver.ConfigCodec, []byte(raw), cfg); err != nil {
		return fmt.Errorf("failed decoding operator-supplied AuthenticationConfiguration in ConfigMap %q: %w", name, err)
	}

	if cfg.Anonymous == nil {
		cfg.Anonymous = &apiserverv1beta1.AnonymousAuthConfig{Enabled: true}
	}
	if !cfg.Anonymous.Enabled {
		cfg.Anonymous.Enabled = true
	}
	// An empty Conditions slice means "anonymous on all paths" — broader than what we need;
	// no merge required. Only narrow path-scoped configurations need our paths added.
	if len(cfg.Anonymous.Conditions) > 0 {
		existing := make(map[string]struct{}, len(cfg.Anonymous.Conditions))
		for _, c := range cfg.Anonymous.Conditions {
			existing[c.Path] = struct{}{}
		}
		for _, p := range anonymousAuthDiscoveryPaths {
			if _, ok := existing[p]; !ok {
				cfg.Anonymous.Conditions = append(cfg.Anonymous.Conditions, apiserverv1beta1.AnonymousAuthCondition{Path: p})
			}
		}
	}

	out, err := runtime.Encode(apiserver.ConfigCodec, cfg)
	if err != nil {
		return fmt.Errorf("failed re-encoding AuthenticationConfiguration for ConfigMap %q: %w", name, err)
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[apiserver.DataKeyConfigMapAuthenticationConfig] = string(out)
	return nil
}