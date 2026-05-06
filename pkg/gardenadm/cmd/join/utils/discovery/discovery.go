// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/labstack/gommon/log"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/cert"
	bootstrapapi "k8s.io/cluster-bootstrap/token/api"
	"k8s.io/cluster-bootstrap/token/jws"
	bootstraptokenutil "k8s.io/cluster-bootstrap/token/util"
)

const (
	perRequestTimeout = 30 * time.Second
	discoveryTimeout  = 5 * time.Minute
	retryInterval     = 5 * time.Second
	userAgent         = "gardenadm-discovery"
)

// Discover performs kubeadm-style discovery of the cluster CA. On success it
// returns the verified CA bundle bytes that the caller can trust for the
// subsequent join steps.
func Discover(ctx context.Context, log logr.Logger, address, token string, caCertHashes []string) ([]byte, error) {
	bootstrapID, bootstrapSecret, err := parseBootstrapToken(token)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()

	insecureClient, err := newDiscoveryClient(address, nil)
	if err != nil {
		return nil, fmt.Errorf("building insecure discovery client: %w", err)
	}

	log.Info("Fetching cluster-info ConfigMap (insecure)", "endpoint", address, "tokenID", bootstrapID)
	cm, err := getClusterInfo(ctx, insecureClient, bootstrapID)
	if err != nil {
		return nil, err
	}

	insecureKubeconfig, err := verifyClusterInfo(cm, bootstrapID, bootstrapSecret)
	if err != nil {
		return nil, err
	}

	caBundle, certs, err := extractCACerts(insecureKubeconfig)
	if err != nil {
		return nil, err
	}

	if err := VerifyAny(certs, caCertHashes); err != nil {
		return nil, fmt.Errorf("none of the provided CA cert hashes match the fetched CA: %w", err)
	}

	secureClient, err := newDiscoveryClient(address, caBundle)
	if err != nil {
		return nil, fmt.Errorf("building secure discovery client: %w", err)
	}

	log.Info("Refetching cluster-info ConfigMap (secure)", "endpoint", address, "tokenID", bootstrapID)
	secureCM, err := getClusterInfo(ctx, secureClient, bootstrapID)
	if err != nil {
		return nil, err
	}

	// TODO(jamand): Diff?
	if cm.Data[bootstrapapi.KubeConfigKey] != secureCM.Data[bootstrapapi.KubeConfigKey] {
		return nil, fmt.Errorf("kubeconfig fetched over verified TLS does not match the insecure response")
	}

	return caBundle, nil
}

// newDiscoveryClient builds a clientset for the cluster-info ConfigMap fetch.
//
// caBundle == nil → InsecureSkipTLSVerify (the first, untrusted fetch).
// caBundle != nil → TLS pinned to the bundle (the second fetch after JWS+SPKI verify).
//
// No authentication credentials are set: cluster-info is anonymous-readable.
func newDiscoveryClient(endpoint string, caBundle []byte) (kubernetes.Interface, error) {
	if !strings.HasPrefix(endpoint, "https://") {
		endpoint = "https://" + endpoint
	}

	cfg := &rest.Config{
		Host:      endpoint,
		Timeout:   perRequestTimeout,
		UserAgent: userAgent,
	}
	if caBundle == nil {
		cfg.TLSClientConfig = rest.TLSClientConfig{Insecure: true}
	} else {
		cfg.TLSClientConfig = rest.TLSClientConfig{CAData: caBundle}
	}
	return kubernetes.NewForConfig(cfg)
}

// getClusterInfo polls until the kube-public/cluster-info ConfigMap exists and
// has a JWS annotation for tokenID. Transient errors are absorbed by the
// retry; the most recent error is surfaced if the context expires.
func getClusterInfo(ctx context.Context, client kubernetes.Interface, tokenID string) (*corev1.ConfigMap, error) {
	var (
		cm      *corev1.ConfigMap
		lastErr error
	)

	err := wait.PollUntilContextCancel(ctx, retryInterval, true,
		func(ctx context.Context) (bool, error) {
			fetched, err := client.CoreV1().ConfigMaps(metav1.NamespacePublic).
				Get(ctx, bootstrapapi.ConfigMapClusterInfo, metav1.GetOptions{})
			if err != nil {
				log.Errorf("fetching cluster-info: %s", err.Error())
				lastErr = fmt.Errorf("fetching cluster-info: %w", err)
				return false, nil
			}
			if _, ok := fetched.Data[bootstrapapi.JWSSignatureKeyPrefix+tokenID]; !ok {
				log.Errorf("no JWS annotation for token id %q yet", tokenID)
				lastErr = fmt.Errorf("no JWS annotation for token id %q yet", tokenID)
				return false, nil
			}
			cm = fetched
			return true, nil
		})
	if err != nil {
		if lastErr != nil {
			log.Errorf("polling cluster-info: %s", lastErr.Error())
			return nil, fmt.Errorf("polling cluster-info: %w", lastErr)
		}
		log.Errorf("polling cluster-info: %s", err.Error())
		return nil, fmt.Errorf("polling cluster-info: %w", err)
	}
	return cm, nil
}

// verifyClusterInfo extracts the kubeconfig and JWS signature from the
// cluster-info ConfigMap and returns the kubeconfig bytes if the signature
// verifies under (tokenID, tokenSecret).
func verifyClusterInfo(cm *corev1.ConfigMap, tokenID, tokenSecret string) ([]byte, error) {
	kubeconfig, ok := cm.Data[bootstrapapi.KubeConfigKey]
	if !ok || len(kubeconfig) == 0 {
		return nil, fmt.Errorf("cluster-info ConfigMap is missing the %q data key", bootstrapapi.KubeConfigKey)
	}

	signature, ok := cm.Data[bootstrapapi.JWSSignatureKeyPrefix+tokenID]
	if !ok {
		return nil, fmt.Errorf("cluster-info ConfigMap is missing the JWS annotation for token id %q", tokenID)
	}

	if !jws.DetachedTokenIsValid(signature, kubeconfig, tokenID, tokenSecret) {
		return nil, fmt.Errorf("JWS signature for token id %q did not verify", tokenID)
	}
	return []byte(kubeconfig), nil
}

// parseBootstrapToken validates and splits a bootstrap token "id.secret".
// Validation is constant-time on the secret part to avoid timing side-channels;
// see k8s.io/cluster-bootstrap/token/util.IsValidBootstrapToken.
func parseBootstrapToken(token string) (id, secret string, err error) {
	if !bootstraptokenutil.IsValidBootstrapToken(token) {
		return "", "", fmt.Errorf("invalid bootstrap token format; expected <id>.<secret>")
	}
	parts := strings.SplitN(token, ".", 2)
	return parts[0], parts[1], nil
}

// extractCACerts loads the kubeconfig from cluster-info and returns the CA
// bundle (PEM bytes) and its parsed certificates. The cluster-info kubeconfig
// is single-cluster by construction, so the choice of "first cluster with CA
// data" is unambiguous in practice.
func extractCACerts(kubeconfig []byte) (caBundle []byte, certs []*x509.Certificate, err error) {
	apiConfig, err := clientcmd.Load(kubeconfig)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to load raw kubeconfig: %w", err)
	}

	for _, cluster := range apiConfig.Clusters {
		if len(cluster.CertificateAuthorityData) > 0 {
			caBundle = cluster.CertificateAuthorityData
			break
		}
	}
	if len(caBundle) == 0 {
		return nil, nil, fmt.Errorf("no certificate authority data found in kubeconfig clusters")
	}

	certs, err = cert.ParseCertsPEM(caBundle)
	if err != nil {
		log.Info(caBundle)
		return nil, nil, fmt.Errorf("failed to parse CA certificates from PEM: %w", err)
	}

	return caBundle, certs, nil
}
