// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package clusterinfo_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/tools/clientcmd"
	bootstrapapi "k8s.io/cluster-bootstrap/token/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/gardener/pkg/utils/kubernetes/clusterinfo"
)

const adminKubeconfigYAML = `apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: Y2EtY2VydA==
    server: https://api.test.example.com
  name: shoot
contexts:
- context:
    cluster: shoot
    user: admin
  name: shoot
current-context: shoot
users:
- name: admin
  user:
    token: secret-token
`

var _ = Describe("ClusterInfo", func() {
	Describe("#BuildKubeconfigFromAdmin", func() {
		It("strips user credentials, contexts, and current-context while preserving clusters", func() {
			out, err := clusterinfo.BuildKubeconfigFromAdmin([]byte(adminKubeconfigYAML))
			Expect(err).NotTo(HaveOccurred())

			cfg, err := clientcmd.Load(out)
			Expect(err).NotTo(HaveOccurred())

			Expect(cfg.AuthInfos).To(BeEmpty())
			Expect(cfg.Contexts).To(BeEmpty())
			Expect(cfg.CurrentContext).To(BeEmpty())

			Expect(cfg.Clusters).To(HaveKey("shoot"))
			Expect(cfg.Clusters["shoot"].Server).To(Equal("https://api.test.example.com"))
			Expect(cfg.Clusters["shoot"].CertificateAuthorityData).To(Equal([]byte("ca-cert")))
		})

		It("returns an error on input that is not a kubeconfig", func() {
			_, err := clusterinfo.BuildKubeconfigFromAdmin([]byte("not a kubeconfig"))
			Expect(err).To(MatchError(ContainSubstring("failed parsing admin kubeconfig")))
		})
	})

	Describe("#Publish", func() {
		var (
			ctx context.Context
			c   client.Client
		)

		BeforeEach(func() {
			ctx = context.Background()
			c = fakeclient.NewClientBuilder().Build()
		})

		It("creates the cluster-info ConfigMap with the supplied kubeconfig payload", func() {
			Expect(clusterinfo.Publish(ctx, c, []byte("payload"))).To(Succeed())

			cm := &corev1.ConfigMap{}
			Expect(c.Get(ctx, client.ObjectKey{Name: "cluster-info", Namespace: "kube-public"}, cm)).To(Succeed())
			Expect(cm.Data).To(HaveKeyWithValue(bootstrapapi.KubeConfigKey, "payload"))
		})

		It("creates a Role + RoleBinding granting system:unauthenticated get access to cluster-info", func() {
			Expect(clusterinfo.Publish(ctx, c, []byte("payload"))).To(Succeed())

			role := &rbacv1.Role{}
			Expect(c.Get(ctx, client.ObjectKey{Name: clusterinfo.RoleName, Namespace: "kube-public"}, role)).To(Succeed())
			Expect(role.Rules).To(ConsistOf(rbacv1.PolicyRule{
				APIGroups:     []string{""},
				Resources:     []string{"configmaps"},
				ResourceNames: []string{"cluster-info"},
				Verbs:         []string{"get"},
			}))

			rb := &rbacv1.RoleBinding{}
			Expect(c.Get(ctx, client.ObjectKey{Name: clusterinfo.RoleName, Namespace: "kube-public"}, rb)).To(Succeed())
			Expect(rb.RoleRef).To(Equal(rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "Role",
				Name:     clusterinfo.RoleName,
			}))
			Expect(rb.Subjects).To(ConsistOf(rbacv1.Subject{
				APIGroup: rbacv1.GroupName,
				Kind:     rbacv1.GroupKind,
				Name:     "system:unauthenticated",
			}))
		})

		It("is idempotent across re-runs", func() {
			Expect(clusterinfo.Publish(ctx, c, []byte("payload"))).To(Succeed())
			Expect(clusterinfo.Publish(ctx, c, []byte("payload"))).To(Succeed())
		})

		It("preserves foreign annotations on the ConfigMap (e.g. bootstrap-signer JWS)", func() {
			Expect(clusterinfo.Publish(ctx, c, []byte("payload"))).To(Succeed())

			cm := &corev1.ConfigMap{}
			Expect(c.Get(ctx, client.ObjectKey{Name: "cluster-info", Namespace: "kube-public"}, cm)).To(Succeed())
			if cm.Annotations == nil {
				cm.Annotations = map[string]string{}
			}
			cm.Annotations["jws-kubeconfig-abcdef"] = "fake-signature"
			Expect(c.Update(ctx, cm)).To(Succeed())

			Expect(clusterinfo.Publish(ctx, c, []byte("payload"))).To(Succeed())

			Expect(c.Get(ctx, client.ObjectKey{Name: "cluster-info", Namespace: "kube-public"}, cm)).To(Succeed())
			Expect(cm.Annotations).To(HaveKeyWithValue("jws-kubeconfig-abcdef", "fake-signature"))
		})

		It("rotates the kubeconfig payload on subsequent publishes (CA-rotation case)", func() {
			Expect(clusterinfo.Publish(ctx, c, []byte("old-ca"))).To(Succeed())
			Expect(clusterinfo.Publish(ctx, c, []byte("new-ca"))).To(Succeed())

			cm := &corev1.ConfigMap{}
			Expect(c.Get(ctx, client.ObjectKey{Name: "cluster-info", Namespace: "kube-public"}, cm)).To(Succeed())
			Expect(cm.Data).To(HaveKeyWithValue(bootstrapapi.KubeConfigKey, "new-ca"))
		})
	})
})
