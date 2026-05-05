// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// SHA-256 SPKI pin compute and verify.
// Algorithm follows kubeadm (k8s.io/kubernetes/cmd/kubeadm/app/util/pubkeypin); we use the same
// "sha256:<hex>" format so --discovery-token-ca-cert-hash is interchangeable.
package discovery

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

const formatPrefix = "sha256:"

// Hash returns the SHA-256 of the cert's SubjectPublicKeyInfo, formatted as "sha256:<hex>".
func Hash(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return formatPrefix + hex.EncodeToString(sum[:])
}

// VerifyAny returns nil if any cert in certs matches any of the supplied pins.
// Each pin must be formatted "sha256:<64-hex-chars>".
func VerifyAny(certs []*x509.Certificate, pins []string) error {
	allowed := make(map[string]bool, len(pins))
	for _, p := range pins {
		if !strings.HasPrefix(p, formatPrefix) {
			return fmt.Errorf("pin %q: only %s<hex> is supported", p, formatPrefix)
		}
		h := strings.ToLower(strings.TrimPrefix(p, formatPrefix))
		if _, err := hex.DecodeString(h); err != nil || len(h) != sha256.Size*2 {
			return fmt.Errorf("pin %q: expected %d hex chars", p, sha256.Size*2)
		}
		allowed[h] = true
	}
	for _, cert := range certs {
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if allowed[hex.EncodeToString(sum[:])] {
			return nil
		}
	}
	return fmt.Errorf("none of the certs match any pinned hash")
}
