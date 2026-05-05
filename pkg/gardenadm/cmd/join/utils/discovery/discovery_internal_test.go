// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	bootstrapapi "k8s.io/cluster-bootstrap/token/api"
	"k8s.io/cluster-bootstrap/token/jws"
)

const (
	testTokenID     = "abcdef"
	testTokenSecret = "0123456789abcdef"
	testKubeconfig  = `apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: Y2EtY2VydA==
    server: https://api.test.example.com
  name: shoot
`
)

func mustComputeJWS(content, id, secret string) string {
	sig, err := jws.ComputeDetachedSignature(content, id, secret)
	Expect(err).NotTo(HaveOccurred())
	return sig
}

func clusterInfo(data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: bootstrapapi.ConfigMapClusterInfo, Namespace: metav1.NamespacePublic},
		Data:       data,
	}
}

var _ = Describe("getClusterInfo", func() {
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)

	BeforeEach(func() {
		// Tight deadline so the "polling exhausts" tests don't hold up the suite.
		ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
		DeferCleanup(cancel)
	})

	It("returns the ConfigMap when both kubeconfig and JWS annotation are present", func() {
		cm := clusterInfo(map[string]string{
			bootstrapapi.KubeConfigKey:                          testKubeconfig,
			bootstrapapi.JWSSignatureKeyPrefix + testTokenID:    mustComputeJWS(testKubeconfig, testTokenID, testTokenSecret),
		})
		client := fake.NewSimpleClientset(cm)

		got, err := getClusterInfo(ctx, client, testTokenID)
		Expect(err).NotTo(HaveOccurred())
		Expect(got.Name).To(Equal(bootstrapapi.ConfigMapClusterInfo))
	})

	It("times out with a fetching error when the ConfigMap doesn't exist", func() {
		client := fake.NewSimpleClientset() // empty
		_, err := getClusterInfo(ctx, client, testTokenID)
		Expect(err).To(MatchError(ContainSubstring("fetching cluster-info")))
	})

	It("times out with an annotation error when the ConfigMap exists but lacks the JWS annotation", func() {
		cm := clusterInfo(map[string]string{
			bootstrapapi.KubeConfigKey: testKubeconfig,
		})
		client := fake.NewSimpleClientset(cm)

		_, err := getClusterInfo(ctx, client, testTokenID)
		Expect(err).To(MatchError(ContainSubstring("no JWS annotation for token id")))
	})

	It("times out with an annotation error when the JWS annotation is for a different token", func() {
		cm := clusterInfo(map[string]string{
			bootstrapapi.KubeConfigKey: testKubeconfig,
			bootstrapapi.JWSSignatureKeyPrefix + "deadbe": "anything",
		})
		client := fake.NewSimpleClientset(cm)

		_, err := getClusterInfo(ctx, client, testTokenID)
		Expect(err).To(MatchError(ContainSubstring("no JWS annotation for token id \"abcdef\"")))
	})
})

var _ = Describe("verifyClusterInfo", func() {
	It("returns kubeconfig bytes on a valid signature", func() {
		cm := clusterInfo(map[string]string{
			bootstrapapi.KubeConfigKey:                          testKubeconfig,
			bootstrapapi.JWSSignatureKeyPrefix + testTokenID:    mustComputeJWS(testKubeconfig, testTokenID, testTokenSecret),
		})
		got, err := verifyClusterInfo(cm, testTokenID, testTokenSecret)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal(testKubeconfig))
	})

	It("errors when the kubeconfig data key is missing", func() {
		cm := clusterInfo(map[string]string{
			bootstrapapi.JWSSignatureKeyPrefix + testTokenID: "ignored",
		})
		_, err := verifyClusterInfo(cm, testTokenID, testTokenSecret)
		Expect(err).To(MatchError(ContainSubstring("missing the \"kubeconfig\" data key")))
	})

	It("errors when the JWS annotation is missing", func() {
		cm := clusterInfo(map[string]string{bootstrapapi.KubeConfigKey: testKubeconfig})
		_, err := verifyClusterInfo(cm, testTokenID, testTokenSecret)
		Expect(err).To(MatchError(ContainSubstring("missing the JWS annotation")))
	})

	It("errors when the signature was made for a different secret", func() {
		cm := clusterInfo(map[string]string{
			bootstrapapi.KubeConfigKey:                          testKubeconfig,
			bootstrapapi.JWSSignatureKeyPrefix + testTokenID:    mustComputeJWS(testKubeconfig, testTokenID, "ffffffffffffffff"),
		})
		_, err := verifyClusterInfo(cm, testTokenID, testTokenSecret)
		Expect(err).To(MatchError(ContainSubstring("did not verify")))
	})

	It("errors when the kubeconfig content was tampered after signing", func() {
		signature := mustComputeJWS(testKubeconfig, testTokenID, testTokenSecret)
		cm := clusterInfo(map[string]string{
			bootstrapapi.KubeConfigKey:                          testKubeconfig + "\n# tampered",
			bootstrapapi.JWSSignatureKeyPrefix + testTokenID:    signature,
		})
		_, err := verifyClusterInfo(cm, testTokenID, testTokenSecret)
		Expect(err).To(MatchError(ContainSubstring("did not verify")))
	})
})

var _ = Describe("extractCACerts", func() {
	var (
		cert       *x509.Certificate
		caPEM      []byte
		kubeconfig []byte
	)

	BeforeEach(func() {
		cert = generateInternalTestCert()
		caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		kubeconfig = buildKubeconfigWithCABase64(base64.StdEncoding.EncodeToString(caPEM))
	})

	It("returns the CA bundle and parsed certs for a single-cert kubeconfig", func() {
		bundle, certs, err := extractCACerts(kubeconfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(bundle).To(Equal(caPEM))
		Expect(certs).To(HaveLen(1))
		Expect(certs[0].Equal(cert)).To(BeTrue())
	})

	It("returns all certs when the bundle contains a chain", func() {
		cert2 := generateInternalTestCert()
		cert2PEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw})
		chainPEM := append([]byte{}, caPEM...)
		chainPEM = append(chainPEM, cert2PEM...)
		kc := buildKubeconfigWithCABase64(base64.StdEncoding.EncodeToString(chainPEM))

		bundle, certs, err := extractCACerts(kc)
		Expect(err).NotTo(HaveOccurred())
		Expect(bundle).To(Equal(chainPEM))
		Expect(certs).To(HaveLen(2))
	})

	It("errors when no cluster has CA data", func() {
		emptyKC := []byte(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://api.example.com
  name: shoot
`)
		_, _, err := extractCACerts(emptyKC)
		Expect(err).To(MatchError(ContainSubstring("no certificate authority data")))
	})

	It("errors when input is not a parseable kubeconfig", func() {
		_, _, err := extractCACerts([]byte("definitely not a kubeconfig"))
		Expect(err).To(MatchError(ContainSubstring("unable to load")))
	})

	It("errors when CA data decodes to non-PEM bytes", func() {
		// "not-a-pem" base64-encoded → kubeconfig parses fine; PEM parse fails.
		kc := buildKubeconfigWithCABase64(base64.StdEncoding.EncodeToString([]byte("not-a-pem")))
		_, _, err := extractCACerts(kc)
		Expect(err).To(MatchError(ContainSubstring("PEM")))
	})
})

func generateInternalTestCert() *x509.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	Expect(err).NotTo(HaveOccurred())
	parsed, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return parsed
}

func buildKubeconfigWithCABase64(caB64 string) []byte {
	return fmt.Appendf(nil, `apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: %s
    server: https://api.test.example.com
  name: shoot
`, caB64)
}
