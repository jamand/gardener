// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"

	kubeapiserver "github.com/gardener/gardener/pkg/component/kubernetes/apiserver"
)

// anonymousAuthDiscoveryPaths are the only paths on which anonymous access must be enabled
// for the kubeadm-style bootstrap discovery flow (cluster-info fetch).
var anonymousAuthDiscoveryPaths = []string{
	"/api/v1/namespaces/kube-public/configmaps/cluster-info",
}

// BuildAnonymousAuthConfig returns an AuthenticationConfiguration YAML that enables anonymous
// access only on the discovery paths required for `gardenadm connect`.
func BuildAnonymousAuthConfig() (string, error) {
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

	out, err := runtime.Encode(kubeapiserver.ConfigCodec, cfg)
	if err != nil {
		return "", fmt.Errorf("failed encoding anonymous AuthenticationConfiguration: %w", err)
	}
	return string(out), nil
}
