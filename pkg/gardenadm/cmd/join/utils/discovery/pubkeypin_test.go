// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package discovery_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/gardener/gardener/pkg/gardenadm/cmd/join/utils/discovery"
)

var _ = Describe("Pubkeypin", func() {
	var (
		cert     *x509.Certificate
		certHash string
	)

	BeforeEach(func() {
		cert = generateTestCert()
		certHash = Hash(cert)
	})

	Describe("#Hash", func() {
		It("returns sha256:<64 lowercase hex chars>", func() {
			Expect(certHash).To(MatchRegexp(`^sha256:[a-f0-9]{64}$`))
		})

		It("is deterministic for the same cert", func() {
			Expect(Hash(cert)).To(Equal(certHash))
		})

		It("differs between different certs", func() {
			Expect(Hash(generateTestCert())).NotTo(Equal(certHash))
		})
	})

	Describe("#VerifyAny", func() {
		Context("with invalid pin format", func() {
			DescribeTable("returns a descriptive error",
				func(pin string, expectedSubstring string) {
					err := VerifyAny([]*x509.Certificate{cert}, []string{pin})
					Expect(err).To(MatchError(ContainSubstring(expectedSubstring)))
				},
				Entry("missing format prefix", "abcdef", "only sha256:"),
				Entry("unsupported algorithm", "md5:abc", "only sha256:"),
				Entry("non-hex characters", "sha256:zzz"+strings.Repeat("a", 61), "expected 64 hex chars"),
				Entry("too short", "sha256:abc", "expected 64 hex chars"),
				Entry("too long (even length)", "sha256:"+strings.Repeat("a", 66), "expected 64 hex chars"),
			)
		})

		Context("with valid input", func() {
			It("succeeds when the pin matches the cert", func() {
				Expect(VerifyAny([]*x509.Certificate{cert}, []string{certHash})).To(Succeed())
			})

			It("succeeds when one of multiple pins matches", func() {
				zeros := "sha256:" + strings.Repeat("0", 64)
				Expect(VerifyAny(
					[]*x509.Certificate{cert},
					[]string{zeros, certHash},
				)).To(Succeed())
			})

			It("succeeds when the pin matches one of multiple certs in the bundle", func() {
				other := generateTestCert()
				Expect(VerifyAny(
					[]*x509.Certificate{other, cert},
					[]string{certHash},
				)).To(Succeed())
			})

			It("ignores case in the pin's hex part", func() {
				upper := "sha256:" + strings.ToUpper(strings.TrimPrefix(certHash, "sha256:"))
				Expect(VerifyAny([]*x509.Certificate{cert}, []string{upper})).To(Succeed())
			})

			It("returns an error when no pin matches", func() {
				wrong := "sha256:" + hex.EncodeToString(make([]byte, 32))
				Expect(VerifyAny([]*x509.Certificate{cert}, []string{wrong})).To(
					MatchError(ContainSubstring("none of the certs match")))
			})

			It("returns an error when no pins are provided", func() {
				Expect(VerifyAny([]*x509.Certificate{cert}, nil)).To(
					MatchError(ContainSubstring("none of the certs match")))
			})

			It("returns an error when no certs are provided", func() {
				Expect(VerifyAny(nil, []string{certHash})).To(
					MatchError(ContainSubstring("none of the certs match")))
			})
		})
	})
})

func generateTestCert() *x509.Certificate {
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

	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return cert
}
