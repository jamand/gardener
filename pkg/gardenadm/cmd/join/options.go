// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package join

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"

	"github.com/gardener/gardener/pkg/gardenadm/cmd"
	"github.com/gardener/gardener/pkg/gardenadm/cmd/join/utils/discovery"
)

// Options contains options for this command.
type Options struct {
	*cmd.Options

	// ControlPlaneAddress is the address of the control plane to which the node should be joined.
	ControlPlaneAddress string
	// BootstrapToken is the bootstrap token to use for joining the node.
	BootstrapToken string
	// CertificateAuthority is the CA bundle of the control plane.
	CertificateAuthority []byte
	// DiscoveryTokenCACertHash carries one or more SHA-256 SPKI pins of the cluster CA, formatted
	// as "sha256:<64-hex>", as emitted by `gardenadm token create --print-join-command`. Multiple
	// pins are tried in order; any match satisfies discovery. Mutually exclusive with CertificateAuthority.
	DiscoveryTokenCACertHash []string
	// WorkerPoolName is the name of the worker pool to use for the join command. If not provided, the node is assigned
	// to the first worker pool in the Shoot manifest.
	WorkerPoolName string
	// ControlPlane indicates whether the node should be joined as a control plane node.
	ControlPlane bool
	// Zone is the availability zone in which the new node is being joined.
	// It is validated against the `.spec.provider.workers[].zones` field of the Shoot manifest.
	// If the worker pool has multiple zones configured, this flag is required.
	// If it has exactly one zone configured, that zone is automatically applied and the flag is optional.
	// If it has no zones configured, this flag must not be set.
	Zone string
}

// ParseArgs parses the arguments to the options.
func (o *Options) ParseArgs(args []string) error {
	if len(args) > 0 {
		o.ControlPlaneAddress = strings.TrimSpace(args[0])
	}

	return nil
}

// Validate validates the options.
func (o *Options) Validate() error {
	if len(o.BootstrapToken) == 0 {
		return fmt.Errorf("must provide a bootstrap token")
	}

	if o.ControlPlane && o.WorkerPoolName != "" {
		return fmt.Errorf("cannot provide a worker pool name when joining a control plane node")
	}

	haveCA := len(o.CertificateAuthority) > 0
	haveHashes := len(o.DiscoveryTokenCACertHash) > 0

	switch {
	case haveCA && haveHashes:
		return fmt.Errorf("--ca-certificate and --discovery-token-ca-cert-hash are mutually exclusive")
	case !haveCA && !haveHashes:
		return fmt.Errorf("must provide one of --ca-certificate and --discovery-token-ca-cert-hash")
	}
	for _, pin := range o.DiscoveryTokenCACertHash {
		if err := discovery.ValidatePinFormat(pin); err != nil {
			return fmt.Errorf("invalid --discovery-token-ca-cert-hash: %w", err)
		}
	}

	return nil
}

// Complete completes the options.
func (o *Options) Complete() error { return nil }

func (o *Options) addFlags(fs *pflag.FlagSet) {
	fs.BytesBase64Var(&o.CertificateAuthority, "ca-certificate", nil, "Base64-encoded certificate authority bundle of the control plane")
	fs.StringSliceVar(&o.DiscoveryTokenCACertHash, "discovery-token-ca-cert-hash", nil, "SHA-256 SPKI pin of the control-plane CA in the form 'sha256:<64-hex>', as emitted by 'gardenadm token create --print-join-command'. May be repeated.")
	fs.StringVar(&o.BootstrapToken, "bootstrap-token", "", "Bootstrap token for joining the cluster (create it with 'gardenadm token' on a control plane node)")
	fs.StringVarP(&o.WorkerPoolName, "worker-pool-name", "w", "", "Name of the worker pool to assign the joining node.")
	fs.BoolVar(&o.ControlPlane, "control-plane", false, "Create a new control plane instance on this node")
	fs.StringVarP(&o.Zone, "zone", "z", "", "Availability zone for the new node. Required if the worker pool in the Shoot has multiple zones configured. Optional if exactly one zone is configured (applied automatically). Must not be set if no zones are configured.")
}
