// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package botanist

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

	It("appends the AuthenticationConfiguration ConfigMap and points StructuredAuthentication at it", func() {
		injectAnonymousAuthConfig(resources)

		Expect(resources.ConfigMaps).To(HaveLen(1))
		cm := resources.ConfigMaps[0]
		Expect(cm.Name).To(Equal(AnonymousAuthConfigMapName))
		Expect(cm.Namespace).To(Equal("garden"))
		Expect(cm.Data).To(HaveKey(apiserver.DataKeyConfigMapAuthenticationConfig))
		Expect(cm.Data[apiserver.DataKeyConfigMapAuthenticationConfig]).To(ContainSubstring("/api/v1/namespaces/kube-public/configmaps/cluster-info"))

		Expect(resources.Shoot.Spec.Kubernetes.KubeAPIServer).NotTo(BeNil())
		Expect(resources.Shoot.Spec.Kubernetes.KubeAPIServer.StructuredAuthentication).To(Equal(&gardencorev1beta1.StructuredAuthentication{
			ConfigMapName: AnonymousAuthConfigMapName,
		}))
	})

	It("preserves an operator-supplied StructuredAuthentication", func() {
		resources.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
			StructuredAuthentication: &gardencorev1beta1.StructuredAuthentication{ConfigMapName: "operator-auth"},
		}

		injectAnonymousAuthConfig(resources)

		Expect(resources.Shoot.Spec.Kubernetes.KubeAPIServer.StructuredAuthentication.ConfigMapName).To(Equal("operator-auth"))
		Expect(resources.ConfigMaps).To(HaveLen(1), "the ConfigMap is still appended even if it is unreferenced")
	})
})
