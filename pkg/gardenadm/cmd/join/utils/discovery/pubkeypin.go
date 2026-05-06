// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package discovery

// SHA-256 SPKI pin compute and verify. Algorithm follows kubeadm (see
// k8s.io/kubernetes/cmd/kubeadm/app/util/pubkeypin); the "sha256:<hex>" format is
// identical so --discovery-token-ca-cert-hash is interchangeable.

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

// ValidatePinFormat checks that pin parses as "sha256:<64-hex-chars>". Callers
// should use this at flag-parse time so malformed input fails fast — VerifyAny
// reports the same errors but only after a network round-trip.
func ValidatePinFormat(pin string) error {
	if !strings.HasPrefix(pin, formatPrefix) {
		return fmt.Errorf("pin %q: only %s<hex> is supported", pin, formatPrefix)
	}
	h := strings.ToLower(strings.TrimPrefix(pin, formatPrefix))
	if _, err := hex.DecodeString(h); err != nil || len(h) != sha256.Size*2 {
		return fmt.Errorf("pin %q: expected %d hex chars", pin, sha256.Size*2)
	}
	return nil
}

// VerifyAny returns nil if any cert in certs matches any of the supplied pins.
// Each pin must be formatted "sha256:<64-hex-chars>".
func VerifyAny(certs []*x509.Certificate, pins []string) error {
	allowed := make(map[string]bool, len(pins))
	for _, p := range pins {
		if err := ValidatePinFormat(p); err != nil {
			return err
		}
		allowed[strings.ToLower(strings.TrimPrefix(p, formatPrefix))] = true
	}
	for _, cert := range certs {
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if allowed[hex.EncodeToString(sum[:])] {
			return nil
		}
	}
	return fmt.Errorf("none of the certs match any pinned hash")
}
