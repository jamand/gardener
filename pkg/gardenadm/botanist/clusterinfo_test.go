// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package botanist_test

import (
	"context"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/gardener/pkg/client/kubernetes"
	fakekubernetes "github.com/gardener/gardener/pkg/client/kubernetes/fake"
	. "github.com/gardener/gardener/pkg/gardenadm/botanist"
	"github.com/gardener/gardener/pkg/gardenlet/operation"
	botanistpkg "github.com/gardener/gardener/pkg/gardenlet/operation/botanist"
	"github.com/gardener/gardener/pkg/gardenlet/operation/shoot"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	fakesecretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager/fake"
)

var _ = Describe("ClusterInfo", func() {
	var (
		ctx context.Context

		namespace string

		fakeSeedClient    client.Client
		fakeSecretManager secretsmanager.Interface

		b *GardenadmBotanist
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

	BeforeEach(func() {
		ctx = context.Background()
		namespace = "kube-system"

		fakeSeedClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.SeedScheme).Build()
		fakeSecretManager = fakesecretsmanager.New(fakeSeedClient, namespace)

		b = &GardenadmBotanist{
			Botanist: &botanistpkg.Botanist{
				Operation: &operation.Operation{
					Logger:         logr.Discard(),
					Shoot:          &shoot.Shoot{},
					SecretsManager: fakeSecretManager,
					SeedClientSet: fakekubernetes.
						NewClientSetBuilder().
						WithClient(fakeSeedClient).
						WithRESTConfig(&rest.Config{}).
						Build(),
				},
			},
		}
	})

	Describe("#PublishClusterInfo", func() {
		Context("when the admin kubeconfig secret is missing", func() {
			It("should fail", func() {
				Expect(b.PublishClusterInfo(ctx)).To(MatchError(ContainSubstring("user-kubeconfig")))
			})
		})

		Context("when the admin kubeconfig secret exists", func() {
			BeforeEach(func() {
				Expect(fakeSeedClient.Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "user-kubeconfig", Namespace: namespace},
					Data:       map[string][]byte{"kubeconfig": []byte(adminKubeconfigYAML)},
				})).To(Succeed())
			})

			It("should publish a credential-less cluster-info ConfigMap", func() {
				Expect(b.PublishClusterInfo(ctx)).To(Succeed())

				cm := &corev1.ConfigMap{}
				Expect(fakeSeedClient.Get(ctx, client.ObjectKey{Name: "cluster-info", Namespace: "kube-public"}, cm)).To(Succeed())

				cfg, err := clientcmd.Load([]byte(cm.Data["kubeconfig"]))
				Expect(err).NotTo(HaveOccurred())

				Expect(cfg.Clusters).To(HaveKey("shoot"))
				Expect(cfg.Clusters["shoot"].Server).To(Equal("https://api.test.example.com"))
				Expect(cfg.Clusters["shoot"].CertificateAuthorityData).To(Equal([]byte("ca-cert")))

				Expect(cfg.AuthInfos).To(BeEmpty())
				Expect(cfg.Contexts).To(BeEmpty())
				Expect(cfg.CurrentContext).To(BeEmpty())
			})

			It("should grant system:unauthenticated get on cluster-info via Role + RoleBinding", func() {
				Expect(b.PublishClusterInfo(ctx)).To(Succeed())

				role := &rbacv1.Role{}
				Expect(fakeSeedClient.Get(ctx, client.ObjectKey{Name: "kubeadm:bootstrap-signer-clusterinfo", Namespace: "kube-public"}, role)).To(Succeed())
				Expect(role.Rules).To(ConsistOf(rbacv1.PolicyRule{
					APIGroups:     []string{""},
					Resources:     []string{"configmaps"},
					ResourceNames: []string{"cluster-info"},
					Verbs:         []string{"get"},
				}))

				rb := &rbacv1.RoleBinding{}
				Expect(fakeSeedClient.Get(ctx, client.ObjectKey{Name: "kubeadm:bootstrap-signer-clusterinfo", Namespace: "kube-public"}, rb)).To(Succeed())
				Expect(rb.RoleRef).To(Equal(rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     "kubeadm:bootstrap-signer-clusterinfo",
				}))
				Expect(rb.Subjects).To(ConsistOf(rbacv1.Subject{
					APIGroup: rbacv1.GroupName,
					Kind:     rbacv1.GroupKind,
					Name:     "system:unauthenticated",
				}))
			})

			It("should be idempotent", func() {
				Expect(b.PublishClusterInfo(ctx)).To(Succeed())
				Expect(b.PublishClusterInfo(ctx)).To(Succeed())
			})

			It("should preserve foreign annotations on re-run (e.g. bootstrap-signer JWS)", func() {
				Expect(b.PublishClusterInfo(ctx)).To(Succeed())

				cm := &corev1.ConfigMap{}
				Expect(fakeSeedClient.Get(ctx, client.ObjectKey{Name: "cluster-info", Namespace: "kube-public"}, cm)).To(Succeed())
				if cm.Annotations == nil {
					cm.Annotations = map[string]string{}
				}
				cm.Annotations["jws-kubeconfig-abcdef"] = "fake-signature"
				Expect(fakeSeedClient.Update(ctx, cm)).To(Succeed())

				Expect(b.PublishClusterInfo(ctx)).To(Succeed())

				Expect(fakeSeedClient.Get(ctx, client.ObjectKey{Name: "cluster-info", Namespace: "kube-public"}, cm)).To(Succeed())
				Expect(cm.Annotations).To(HaveKeyWithValue("jws-kubeconfig-abcdef", "fake-signature"))
			})
		})
	})
})
