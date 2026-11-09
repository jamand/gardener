// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"fmt"
	"net"
	"time"

	machinev1alpha1 "github.com/gardener/machine-controller-manager/pkg/apis/machine/v1alpha1"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1beta1helper "github.com/gardener/gardener/pkg/api/core/v1beta1/helper"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/component"
	"github.com/gardener/gardener/pkg/controllerutils"
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/gardener/gardener/pkg/utils/flow"
)

const (
	// DefaultInterval is the default interval for retry operations.
	DefaultInterval = 5 * time.Second
	// DefaultSevereThreshold is the default threshold until an error reported by another component is treated as 'severe'.
	DefaultSevereThreshold = 30 * time.Second
	// DefaultTimeout is the default timeout and defines how long Gardener should wait
	// for a successful reconciliation of a network resource.
	DefaultTimeout = 3 * time.Minute
)

// TimeNow returns the current time. Exposed for testing.
var TimeNow = time.Now

// Interface is an interface for managing the network CRD deployment.
type Interface interface {
	component.DeployMigrateWaiter
	SetPodCIDRs([]net.IPNet)
	SetServiceCIDRs([]net.IPNet)
	Get(ctx context.Context) (*extensionsv1alpha1.Network, error)
	// DeleteStaleResources deletes Network resources of other networking types than the shoot's current one (left over
	// from changing the networking type), once no Machine or MachineSet uses their networking type anymore.
	DeleteStaleResources(ctx context.Context) error
	// WaitCleanupStaleResources waits until all stale Network resources that are no longer in use are cleaned up.
	WaitCleanupStaleResources(ctx context.Context) error
}

// Values contains the values used to create a Network CRD
type Values struct {
	// Namespace is the namespace of the Shoot network in the Seed
	Namespace string
	// Name is the name of the Network extension. Commonly the Shoot's name. When the networking type is changed, the
	// Network extension for the new type is named "<Name>-<Type>".
	Name string
	// Type is the type of Network plugin/extension (e.g calico)
	Type string
	// IPFamilies specifies the IP protocol versions to use for shoot networking.
	IPFamilies []extensionsv1alpha1.IPFamily
	// ProviderConfig contains the provider config for the Network extension.
	ProviderConfig *runtime.RawExtension
	// PodCIDRs are the Shoot's pod CIDRs in the Shoot VPC
	PodCIDRs []net.IPNet
	// ServiceCIDRs are the Shoot's service CIDRs in the Shoot VPC
	ServiceCIDRs []net.IPNet
}

// New creates a new instance of DeployWaiter for a Network.
func New(
	log logr.Logger,
	client client.Client,
	values *Values,
	waitInterval time.Duration,
	waitSevereThreshold time.Duration,
	waitTimeout time.Duration,
) Interface {
	return &network{
		client:              client,
		log:                 log,
		values:              values,
		waitInterval:        waitInterval,
		waitSevereThreshold: waitSevereThreshold,
		waitTimeout:         waitTimeout,

		network: &extensionsv1alpha1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name:      values.Name,
				Namespace: values.Namespace,
			},
		},
	}
}

type network struct {
	values              *Values
	log                 logr.Logger
	client              client.Client
	waitInterval        time.Duration
	waitSevereThreshold time.Duration
	waitTimeout         time.Duration

	network *extensionsv1alpha1.Network
	// staleNetworks are the existing Network objects of other networking types than the shoot's current one.
	staleNetworks []*extensionsv1alpha1.Network
	resolved      bool
}

// Deploy uses the seed client to create or update the Network custom resource in the Shoot namespace in the Seed.
// Stale Network resources of other networking types are kept unchanged but are triggered for reconciliation.
func (n *network) Deploy(ctx context.Context) error {
	if err := n.resolve(ctx); err != nil {
		return err
	}

	if _, err := n.deploy(ctx, v1beta1constants.GardenerOperationReconcile); err != nil {
		return err
	}

	var fns []flow.TaskFn
	for _, staleNetwork := range n.staleNetworks {
		fns = append(fns, func(ctx context.Context) error {
			return extensions.AnnotateObjectWithOperation(ctx, n.client, staleNetwork, v1beta1constants.GardenerOperationReconcile)
		})
	}

	return flow.Parallel(fns...)(ctx)
}

// Restore uses the seed client and the ShootState to create the Network custom resource in the Shoot namespace in the Seed and restore its state
func (n *network) Restore(ctx context.Context, shootState *v1beta1.ShootState) error {
	if err := n.resolve(ctx); err != nil {
		return err
	}

	// The Network resources don't exist in the destination seed yet. If the Network resource was created after changing
	// the networking type, restore it under its type-suffixed name so that its state is found in the ShootState.
	name := n.nameForType()
	extensionResourceStates := v1beta1helper.ExtensionResourceStateList(shootState.Spec.Extensions)
	if extensionResourceStates.Get(extensionsv1alpha1.NetworkResource, &name, nil) != nil {
		n.network.Name = name
	}

	return extensions.RestoreExtensionWithDeployFunction(
		ctx,
		n.client,
		shootState,
		extensionsv1alpha1.NetworkResource,
		n.deploy,
	)
}

// Migrate migrates all Network custom resources
func (n *network) Migrate(ctx context.Context) error {
	return extensions.MigrateExtensionObjects(
		ctx,
		n.client,
		&extensionsv1alpha1.NetworkList{},
		n.values.Namespace,
		nil,
	)
}

// WaitMigrate waits until all Network custom resources have been successfully migrated.
func (n *network) WaitMigrate(ctx context.Context) error {
	return extensions.WaitUntilExtensionObjectsMigrated(
		ctx,
		n.client,
		&extensionsv1alpha1.NetworkList{},
		extensionsv1alpha1.NetworkResource,
		n.values.Namespace,
		n.waitInterval,
		n.waitTimeout,
		nil,
	)
}

// Destroy deletes all Network CRDs
func (n *network) Destroy(ctx context.Context) error {
	return extensions.DeleteExtensionObjects(
		ctx,
		n.client,
		&extensionsv1alpha1.NetworkList{},
		n.values.Namespace,
		nil,
	)
}

// Wait waits until the Network CRD and all stale Network CRDs are ready (deployed or restored)
func (n *network) Wait(ctx context.Context) error {
	if err := n.resolve(ctx); err != nil {
		return err
	}

	var fns []flow.TaskFn
	for _, network := range append([]*extensionsv1alpha1.Network{n.network}, n.staleNetworks...) {
		fns = append(fns, func(ctx context.Context) error {
			return extensions.WaitUntilExtensionObjectReady(
				ctx,
				n.client,
				n.log,
				network,
				extensionsv1alpha1.NetworkResource,
				n.waitInterval,
				n.waitSevereThreshold,
				n.waitTimeout,
				nil,
			)
		})
	}

	return flow.ParallelExitOnError(fns...)(ctx)
}

// WaitCleanup waits until all Network CRDs are deleted
func (n *network) WaitCleanup(ctx context.Context) error {
	return extensions.WaitUntilExtensionObjectsDeleted(
		ctx,
		n.client,
		n.log,
		&extensionsv1alpha1.NetworkList{},
		extensionsv1alpha1.NetworkResource,
		n.values.Namespace,
		n.waitInterval,
		n.waitTimeout,
		nil,
	)
}

// DeleteStaleResources deletes Network resources of other networking types than the shoot's current one, once no
// Machine or MachineSet uses their networking type anymore.
func (n *network) DeleteStaleResources(ctx context.Context) error {
	unusedNetworks, err := n.unusedStaleNetworks(ctx)
	if err != nil {
		return err
	}

	var fns []flow.TaskFn
	for _, network := range unusedNetworks {
		fns = append(fns, func(ctx context.Context) error {
			return extensions.DeleteExtensionObject(ctx, n.client, network)
		})
	}

	return flow.Parallel(fns...)(ctx)
}

// WaitCleanupStaleResources waits until all stale Network resources that are no longer in use are cleaned up.
func (n *network) WaitCleanupStaleResources(ctx context.Context) error {
	unusedNetworks, err := n.unusedStaleNetworks(ctx)
	if err != nil {
		return err
	}

	var fns []flow.TaskFn
	for _, network := range unusedNetworks {
		fns = append(fns, func(ctx context.Context) error {
			return extensions.WaitUntilExtensionObjectDeleted(
				ctx,
				n.client,
				n.log,
				network,
				extensionsv1alpha1.NetworkResource,
				n.waitInterval,
				n.waitTimeout,
			)
		})
	}

	return flow.Parallel(fns...)(ctx)
}

// unusedStaleNetworks returns the stale Network resources whose networking type is not used by any Machine or
// MachineSet, i.e., there is no Machine or MachineSet with the networking provider label in its node template.
func (n *network) unusedStaleNetworks(ctx context.Context) ([]*extensionsv1alpha1.Network, error) {
	if err := n.resolve(ctx); err != nil {
		return nil, err
	}

	if len(n.staleNetworks) == 0 {
		return nil, nil
	}

	usedTypes := sets.New[string]()

	machineSetList := &machinev1alpha1.MachineSetList{}
	if err := n.client.List(ctx, machineSetList, client.InNamespace(n.values.Namespace)); err != nil {
		return nil, fmt.Errorf("failed listing MachineSets: %w", err)
	}
	for _, machineSet := range machineSetList.Items {
		if networkingType, ok := machineSet.Spec.Template.Spec.NodeTemplateSpec.Labels[v1beta1constants.LabelNetworkingProvider]; ok {
			usedTypes.Insert(networkingType)
		}
	}

	machineList := &machinev1alpha1.MachineList{}
	if err := n.client.List(ctx, machineList, client.InNamespace(n.values.Namespace)); err != nil {
		return nil, fmt.Errorf("failed listing Machines: %w", err)
	}
	for _, machine := range machineList.Items {
		if networkingType, ok := machine.Spec.NodeTemplateSpec.Labels[v1beta1constants.LabelNetworkingProvider]; ok {
			usedTypes.Insert(networkingType)
		}
	}

	var unusedNetworks []*extensionsv1alpha1.Network
	for _, network := range n.staleNetworks {
		if usedTypes.Has(network.Spec.Type) {
			n.log.Info("Keeping stale Network as its networking type is still used by Machines", "network", client.ObjectKeyFromObject(network), "type", network.Spec.Type)
			continue
		}
		unusedNetworks = append(unusedNetworks, network)
	}

	return unusedNetworks, nil
}

// resolve determines the name of the Network resource for the shoot's current networking type and the stale Network
// resources of other networking types by listing the existing Network resources. When creating a new shoot, the
// Network resource is named after the shoot. When the networking type is changed, a second Network resource with the
// type-suffixed name is created next to the existing ones. The result is computed only once per component instance.
func (n *network) resolve(ctx context.Context) error {
	if n.resolved {
		return nil
	}

	networkList := &extensionsv1alpha1.NetworkList{}
	if err := n.client.List(ctx, networkList, client.InNamespace(n.values.Namespace)); err != nil {
		return fmt.Errorf("failed listing Networks: %w", err)
	}

	if len(networkList.Items) > 0 {
		n.network.Name = n.nameForType()
	}

	for _, network := range networkList.Items {
		if network.Spec.Type == n.values.Type {
			n.network.Name = network.Name
			continue
		}
		n.staleNetworks = append(n.staleNetworks, network.DeepCopy())
	}

	n.resolved = true
	return nil
}

// nameForType returns the type-suffixed name used for the Network resource after changing the networking type.
func (n *network) nameForType() string {
	return n.values.Name + "-" + n.values.Type
}

func getCIDRforSpec(ipFamilies []extensionsv1alpha1.IPFamily, podCIDRs []net.IPNet) string {
	if len(ipFamilies) == 2 && ipFamilies[0] == extensionsv1alpha1.IPFamilyIPv6 {
		return podCIDRs[1].String()
	}
	return podCIDRs[0].String()
}

func (n *network) deploy(ctx context.Context, operation string) (extensionsv1alpha1.Object, error) {
	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, n.client, n.network, func() error {
		metav1.SetMetaDataAnnotation(&n.network.ObjectMeta, v1beta1constants.GardenerOperation, operation)
		metav1.SetMetaDataAnnotation(&n.network.ObjectMeta, v1beta1constants.GardenerTimestamp, TimeNow().UTC().Format(time.RFC3339Nano))

		n.network.Spec = extensionsv1alpha1.NetworkSpec{
			DefaultSpec: extensionsv1alpha1.DefaultSpec{
				Type:           n.values.Type,
				ProviderConfig: n.values.ProviderConfig,
			},
			IPFamilies:  n.values.IPFamilies,
			PodCIDR:     getCIDRforSpec(n.values.IPFamilies, n.values.PodCIDRs),
			ServiceCIDR: getCIDRforSpec(n.values.IPFamilies, n.values.ServiceCIDRs),
		}

		return nil
	})

	return n.network, err
}

func (n *network) SetPodCIDRs(pods []net.IPNet) {
	n.values.PodCIDRs = pods
}

func (n *network) SetServiceCIDRs(services []net.IPNet) {
	n.values.ServiceCIDRs = services
}

// Get retrieves and returns the Network resources based on the configured values.
func (n *network) Get(ctx context.Context) (*extensionsv1alpha1.Network, error) {
	if err := n.resolve(ctx); err != nil {
		return nil, err
	}

	if err := n.client.Get(ctx, client.ObjectKeyFromObject(n.network), n.network); err != nil {
		return nil, err
	}
	return n.network, nil
}
