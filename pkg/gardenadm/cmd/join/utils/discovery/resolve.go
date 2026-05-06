// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"

	"github.com/go-logr/logr"
)

// ResolveCertificateAuthority returns the CA bundle to trust for the bootstrap
// connection. If caBundle is supplied (operator passed --ca-certificate), it is
// returned verbatim. Otherwise the bundle is fetched and verified via the
// kubeadm-style discovery flow against the provided SHA-256 SPKI hashes.
//
// The caller is expected to enforce mutual exclusion of the two inputs at
// validation time; this helper is permissive (caBundle wins if both are set).
func ResolveCertificateAuthority(ctx context.Context, log logr.Logger, address, token string, caBundle []byte, caCertHashes []string) ([]byte, error) {
	if len(caBundle) > 0 {
		return caBundle, nil
	}
	return Discover(ctx, log, address, token, caCertHashes)
}
