// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package botanist

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/component/kubernetes/apiserver"
	"github.com/gardener/gardener/pkg/gardenadm"
)

var _ = Describe("injectAnonymousAuthConfig", func() {
	var resources *gardenadm.Resources

	BeforeEach(func() {
		resources = &gardenadm.Resources{
			Shoot: &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{Name: "root", Namespace: "garden"},
			},
		}
	})

	decode := func(raw string) *apiserverv1beta1.AuthenticationConfiguration {
		out := &apiserverv1beta1.AuthenticationConfiguration{}
		Expect(runtime.DecodeInto(apiserver.ConfigCodec, []byte(raw), out)).To(Succeed())
		return out
	}

	encode := func(cfg *apiserverv1beta1.AuthenticationConfiguration) string {
		cfg.TypeMeta = metav1.TypeMeta{
			APIVersion: apiserverv1beta1.ConfigSchemeGroupVersion.String(),
			Kind:       "AuthenticationConfiguration",
		}
		out, err := runtime.Encode(apiserver.ConfigCodec, cfg)
		Expect(err).NotTo(HaveOccurred())
		return string(out)
	}

	pathsFromConfig := func(cfg *apiserverv1beta1.AuthenticationConfiguration) []string {
		if cfg.Anonymous == nil {
			return nil
		}
		paths := make([]string, 0, len(cfg.Anonymous.Conditions))
		for _, c := range cfg.Anonymous.Conditions {
			paths = append(paths, c.Path)
		}
		return paths
	}

	Context("when the Shoot has no StructuredAuthentication", func() {
		It("appends a default ConfigMap and points StructuredAuthentication at it", func() {
			Expect(injectAnonymousAuthConfig(resources)).To(Succeed())

			Expect(resources.ConfigMaps).To(HaveLen(1))
			cm := resources.ConfigMaps[0]
			Expect(cm.Name).To(Equal(AnonymousAuthConfigMapName))
			Expect(cm.Namespace).To(Equal("garden"))

			cfg := decode(cm.Data[apiserver.DataKeyConfigMapAuthenticationConfig])
			Expect(cfg.Anonymous).NotTo(BeNil())
			Expect(cfg.Anonymous.Enabled).To(BeTrue())
			Expect(pathsFromConfig(cfg)).To(ConsistOf(
				"/api/v1/namespaces/kube-public/configmaps/cluster-info",
			))

			Expect(resources.Shoot.Spec.Kubernetes.KubeAPIServer.StructuredAuthentication).To(Equal(&gardencorev1beta1.StructuredAuthentication{
				ConfigMapName: AnonymousAuthConfigMapName,
			}))
		})
	})

	Context("when the Shoot already references an AuthenticationConfiguration ConfigMap", func() {
		const operatorCMName = "operator-auth"

		BeforeEach(func() {
			resources.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
				StructuredAuthentication: &gardencorev1beta1.StructuredAuthentication{ConfigMapName: operatorCMName},
			}
		})

		It("returns an error when the referenced ConfigMap is not loaded", func() {
			Expect(injectAnonymousAuthConfig(resources)).To(MatchError(ContainSubstring("not loaded from the manifests directory")))
		})

		It("preserves the operator's reference and merges the discovery paths into the existing config", func() {
			operatorCfg := &apiserverv1beta1.AuthenticationConfiguration{
				Anonymous: &apiserverv1beta1.AnonymousAuthConfig{
					Enabled:    true,
					Conditions: []apiserverv1beta1.AnonymousAuthCondition{{Path: "/operator-only"}},
				},
			}
			resources.ConfigMaps = []*corev1.ConfigMap{{
				ObjectMeta: metav1.ObjectMeta{Name: operatorCMName, Namespace: "garden"},
				Data:       map[string]string{apiserver.DataKeyConfigMapAuthenticationConfig: encode(operatorCfg)},
			}}

			Expect(injectAnonymousAuthConfig(resources)).To(Succeed())

			Expect(resources.Shoot.Spec.Kubernetes.KubeAPIServer.StructuredAuthentication.ConfigMapName).To(Equal(operatorCMName))
			Expect(resources.ConfigMaps).To(HaveLen(1), "no extra ConfigMap is appended")

			merged := decode(resources.ConfigMaps[0].Data[apiserver.DataKeyConfigMapAuthenticationConfig])
			Expect(pathsFromConfig(merged)).To(ConsistOf(
				"/operator-only",
				"/api/v1/namespaces/kube-public/configmaps/cluster-info",
			))
		})

		It("does not duplicate the discovery path when the operator already enabled it", func() {
			operatorCfg := &apiserverv1beta1.AuthenticationConfiguration{
				Anonymous: &apiserverv1beta1.AnonymousAuthConfig{
					Enabled: true,
					Conditions: []apiserverv1beta1.AnonymousAuthCondition{
						{Path: "/api/v1/namespaces/kube-public/configmaps/cluster-info"},
						{Path: "/operator-only"},
					},
				},
			}
			resources.ConfigMaps = []*corev1.ConfigMap{{
				ObjectMeta: metav1.ObjectMeta{Name: operatorCMName, Namespace: "garden"},
				Data:       map[string]string{apiserver.DataKeyConfigMapAuthenticationConfig: encode(operatorCfg)},
			}}

			Expect(injectAnonymousAuthConfig(resources)).To(Succeed())

			merged := decode(resources.ConfigMaps[0].Data[apiserver.DataKeyConfigMapAuthenticationConfig])
			Expect(pathsFromConfig(merged)).To(ConsistOf(
				"/api/v1/namespaces/kube-public/configmaps/cluster-info",
				"/operator-only",
			))
		})

		It("leaves an unconditional anonymous-everywhere config alone", func() {
			operatorCfg := &apiserverv1beta1.AuthenticationConfiguration{
				Anonymous: &apiserverv1beta1.AnonymousAuthConfig{Enabled: true},
			}
			resources.ConfigMaps = []*corev1.ConfigMap{{
				ObjectMeta: metav1.ObjectMeta{Name: operatorCMName, Namespace: "garden"},
				Data:       map[string]string{apiserver.DataKeyConfigMapAuthenticationConfig: encode(operatorCfg)},
			}}

			Expect(injectAnonymousAuthConfig(resources)).To(Succeed())

			merged := decode(resources.ConfigMaps[0].Data[apiserver.DataKeyConfigMapAuthenticationConfig])
			Expect(merged.Anonymous).NotTo(BeNil())
			Expect(merged.Anonymous.Enabled).To(BeTrue())
			Expect(merged.Anonymous.Conditions).To(BeEmpty())
		})

		It("initializes Anonymous when the operator's config has none", func() {
			operatorCfg := &apiserverv1beta1.AuthenticationConfiguration{}
			resources.ConfigMaps = []*corev1.ConfigMap{{
				ObjectMeta: metav1.ObjectMeta{Name: operatorCMName, Namespace: "garden"},
				Data:       map[string]string{apiserver.DataKeyConfigMapAuthenticationConfig: encode(operatorCfg)},
			}}

			Expect(injectAnonymousAuthConfig(resources)).To(Succeed())

			merged := decode(resources.ConfigMaps[0].Data[apiserver.DataKeyConfigMapAuthenticationConfig])
			Expect(merged.Anonymous).NotTo(BeNil())
			Expect(merged.Anonymous.Enabled).To(BeTrue())
			// Anonymous starts unset → we set Enabled but leave Conditions empty (broader),
			// since the operator chose not to scope it.
			Expect(merged.Anonymous.Conditions).To(BeEmpty())
		})
	})
})
