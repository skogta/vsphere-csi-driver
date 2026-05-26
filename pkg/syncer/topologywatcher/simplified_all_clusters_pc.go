/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package topologywatcher

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
	cnsvsphere "sigs.k8s.io/vsphere-csi-driver/v3/pkg/common/cns-lib/vsphere"
	"sigs.k8s.io/vsphere-csi-driver/v3/pkg/csi/service/logger"
)

// AllClustersPropertyCollector monitors ALL clusters in vCenter with Host traversal (no Datastore)
// This simplified approach watches:
// - ClusterComputeResource: ESA config, host list changes
// - HostSystem: datastore mounts, ESX version
type AllClustersPropertyCollector struct {
	vc          *cnsvsphere.VirtualCenter
	eventChan   chan InfrastructureEvent
	
	// Safe destruction management
	currentPC   *property.Collector
	pcContext   context.Context
	pcCancel    context.CancelFunc
	isRunning   bool
	isDestroyed bool
	pcMutex     sync.RWMutex
	monitoringWG sync.WaitGroup
	
	// Action handlers
	actionHandlers *InfrastructureActionHandlers
}

// InfrastructureActionHandlers contains placeholder functions for infrastructure REMOVAL changes only
type InfrastructureActionHandlers struct {
	// Host-related REMOVAL actions only
	OnHostRemoved         func(ctx context.Context, hostID string, clusterID string, affectedPolicies []string)
	
	// Datastore-related REMOVAL actions only (detected via Host.datastore changes)
	OnDatastoreUnmounted  func(ctx context.Context, datastoreID string, hostID string)
	
	// Cluster ESA DISABLED action only (ESA enablement is not critical for immediate updates)
	OnClusterESADisabled  func(ctx context.Context, clusterID string, affectedPolicies []string)
}

// NewAllClustersPropertyCollector creates a property collector that monitors ALL clusters
func NewAllClustersPropertyCollector(vc *cnsvsphere.VirtualCenter) *AllClustersPropertyCollector {
	return &AllClustersPropertyCollector{
		vc:        vc,
		eventChan: make(chan InfrastructureEvent, 100),
		actionHandlers: &InfrastructureActionHandlers{
			// Initialize with default placeholder implementations for REMOVAL events only
			OnHostRemoved:        defaultOnHostRemoved,
			OnDatastoreUnmounted: defaultOnDatastoreUnmounted,
			OnClusterESADisabled: defaultOnClusterESADisabled,
		},
	}
}

// SetActionHandlers allows customization of action handlers
func (acpc *AllClustersPropertyCollector) SetActionHandlers(handlers *InfrastructureActionHandlers) {
	acpc.actionHandlers = handlers
}

// GetEventChannel returns the channel for receiving infrastructure events
func (acpc *AllClustersPropertyCollector) GetEventChannel() <-chan InfrastructureEvent {
	return acpc.eventChan
}

// Start begins monitoring ALL clusters in vCenter
func (acpc *AllClustersPropertyCollector) Start(ctx context.Context) error {
	log := logger.GetLogger(ctx)
	log.Infof("Starting all-clusters property collector (monitors ALL clusters in vCenter)")
	
	go acpc.runAllClustersPropertyCollector(ctx)
	return nil
}

// SafeDestroy safely destroys the property collector
func (acpc *AllClustersPropertyCollector) SafeDestroy(ctx context.Context) error {
	acpc.pcMutex.Lock()
	defer acpc.pcMutex.Unlock()
	
	log := logger.GetLogger(ctx)
	
	// 🛡️ SAFETY CHECK 1: Already destroyed?
	if acpc.isDestroyed {
		log.Debugf("All-clusters property collector already destroyed")
		return nil
	}
	
	// 🛡️ SAFETY CHECK 2: Valid property collector?
	if acpc.currentPC == nil {
		log.Debugf("No active all-clusters property collector to destroy")
		acpc.isDestroyed = true
		return nil
	}
	
	log.Infof("Safely destroying all-clusters property collector: %s", acpc.currentPC.Reference().Value)
	
	// 🛡️ STEP 1: Cancel context to signal monitoring loop to stop
	if acpc.pcCancel != nil {
		log.Debugf("Cancelling all-clusters property collector context")
		acpc.pcCancel()
	}
	
	// 🛡️ STEP 2: Wait for monitoring loop to exit gracefully (with timeout)
	if acpc.isRunning {
		log.Debugf("Waiting for all-clusters monitoring loop to exit...")
		
		// Wait for monitoring goroutine to finish
		done := make(chan struct{})
		go func() {
			acpc.monitoringWG.Wait()
			close(done)
		}()
		
		select {
		case <-done:
			log.Debugf("All-clusters monitoring loop exited successfully")
		case <-time.After(10 * time.Second):
			log.Warnf("Timeout waiting for all-clusters monitoring loop to exit")
		}
	}
	
	// 🛡️ STEP 3: Destroy the property collector with timeout
	destroyCtx, destroyCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer destroyCancel()
	
	err := acpc.currentPC.Destroy(destroyCtx)
	if err != nil {
		log.Errorf("Failed to destroy all-clusters property collector: %v", err)
	} else {
		log.Debugf("Successfully destroyed all-clusters property collector")
	}
	
	// 🛡️ STEP 4: Clear all state regardless of destroy error
	acpc.currentPC = nil
	acpc.pcContext = nil
	acpc.pcCancel = nil
	acpc.isRunning = false
	acpc.isDestroyed = true
	
	log.Infof("All-clusters property collector destruction completed")
	return err
}

// runAllClustersPropertyCollector runs the monitoring loop for all clusters
func (acpc *AllClustersPropertyCollector) runAllClustersPropertyCollector(ctx context.Context) {
	log := logger.GetLogger(ctx)
	
	for {
		select {
		case <-ctx.Done():
			log.Infof("All-clusters property collector context cancelled, stopping")
			return
		default:
			log.Infof("Starting all-clusters property collector session")
			
			err := acpc.runSingleAllClustersSession(ctx)
			if err != nil {
				log.Errorf("All-clusters property collector session failed: %v", err)
				
				// Exponential backoff on errors
				select {
				case <-ctx.Done():
					return
				case <-time.After(30 * time.Second):
					log.Infof("Retrying all-clusters property collector after backoff")
				}
			}
		}
	}
}

// runSingleAllClustersSession runs one session of all-clusters property collection
func (acpc *AllClustersPropertyCollector) runSingleAllClustersSession(ctx context.Context) error {
	log := logger.GetLogger(ctx)
	
	// Connect to vCenter
	err := acpc.vc.Connect(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to vCenter: %w", err)
	}
	
	// Create property filter for ALL clusters with Host traversal
	filter, err := acpc.createAllClustersPropertyFilter(ctx)
	if err != nil {
		return fmt.Errorf("failed to create all-clusters property filter: %w", err)
	}
	
	// Create property collector
	pc, err := property.DefaultCollector(acpc.vc.Client.Client).Create(ctx)
	if err != nil {
		return fmt.Errorf("failed to create all-clusters property collector: %w", err)
	}
	
	// 🛡️ SAFE PC MANAGEMENT: Store PC reference and create cancellable context
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	defer sessionCancel() // Ensure context is always cancelled
	
	acpc.pcMutex.Lock()
	acpc.currentPC = pc
	acpc.pcContext = sessionCtx
	acpc.pcCancel = sessionCancel
	acpc.isRunning = true
	acpc.isDestroyed = false
	acpc.monitoringWG.Add(1)
	acpc.pcMutex.Unlock()
	
	// 🛡️ SAFE CLEANUP: Use defer with proper error handling and timeout
	defer func() {
		acpc.monitoringWG.Done() // Signal monitoring has stopped
		
		// Use separate context with timeout for destruction
		destroyCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		if destroyErr := pc.Destroy(destroyCtx); destroyErr != nil {
			log.Errorf("Failed to destroy all-clusters property collector: %v", destroyErr)
		} else {
			log.Debugf("Successfully destroyed all-clusters property collector: %s", pc.Reference().Value)
		}
	}()
	
	log.Infof("Starting all-clusters property collector monitoring session")
	
	// Start monitoring with crash-safe update processing
	err = property.WaitForUpdatesEx(sessionCtx, pc, filter, func(updates []types.ObjectUpdate) bool {
		// 🛡️ SAFETY: Check if context was cancelled before processing
		select {
		case <-sessionCtx.Done():
			log.Debugf("All-clusters property collector context cancelled, stopping monitoring")
			return true // Stop monitoring
		default:
			// Continue with update processing
		}
		
		// Process updates safely with error recovery
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("Panic during all-clusters update processing: %v", r)
				}
			}()
			acpc.processAllClustersUpdates(ctx, updates)
		}()
		
		// Check if context was cancelled during processing
		select {
		case <-sessionCtx.Done():
			log.Debugf("All-clusters property collector context cancelled during processing")
			return true // Stop monitoring
		default:
			return false // Continue monitoring
		}
	})
	
	if err != nil {
		return fmt.Errorf("all-clusters property collector monitoring failed: %w", err)
	}
	
	log.Infof("All-clusters property collector session completed")
	return nil
}

// createAllClustersPropertyFilter creates property filter for ALL clusters with Host traversal
func (acpc *AllClustersPropertyCollector) createAllClustersPropertyFilter(ctx context.Context) (*property.WaitFilter, error) {
	log := logger.GetLogger(ctx)
	
	// Discover ALL clusters in vCenter
	allClusters, err := acpc.discoverAllClusters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to discover all clusters: %w", err)
	}
	
	if len(allClusters) == 0 {
		log.Warnf("No clusters found in vCenter")
		return &property.WaitFilter{}, nil
	}
	
	log.Infof("Creating all-clusters property filter for %d clusters", len(allClusters))
	
	filter := new(property.WaitFilter)
	
	// 🎯 TRAVERSAL SPEC: Cluster -> Host (NO Datastore traversal)
	// This monitors:
	// - ClusterComputeResource properties (ESA config, host list)  
	// - HostSystem properties (datastore mounts, ESX version)
	clusterToHostTraversal := types.TraversalSpec{
		Type: "ClusterComputeResource",
		Path: "host",
		Skip: types.NewBool(false),
		SelectSet: []types.BaseSelectionSpec{
			&types.TraversalSpec{
				Type: "HostSystem",
				Path: "", // No further traversal - we stop at Host level
				Skip: types.NewBool(false),
			},
		},
	}
	
	// Add each cluster to the filter
	for _, cluster := range allClusters {
		clusterMoref := cluster.Reference()
		
		// Add cluster with Host traversal
		filter.Add(clusterMoref, clusterMoref.Type, []string{
			"configuration.vsanConfig", // ESA configuration
			"host",                      // Host list changes
		}, &clusterToHostTraversal)
		
		log.Debugf("Added cluster %s (%s) to all-clusters filter", cluster.Name, clusterMoref.Value)
	}
	
	// 🎯 PROPERTY SPECS: Define what properties to monitor
	// 1. ClusterComputeResource properties
	propCluster := types.PropertySpec{
		Type: "ClusterComputeResource",
		PathSet: []string{
			"configuration.vsanConfig", // ESA status monitoring
			"host",                      // Host list changes
		},
	}
	
	// 2. HostSystem properties (NO Datastore properties - only references)
	propHost := types.PropertySpec{
		Type: "HostSystem",
		PathSet: []string{
			"config.product.version", // ESX version
			"datastore",              // Datastore mount references (not properties)
		},
	}
	
	filter.Spec.PropSet = append(filter.Spec.PropSet, propCluster, propHost)
	
	log.Infof("All-clusters property filter created with %d clusters", len(allClusters))
	return filter, nil
}

// discoverAllClusters discovers ALL clusters in vCenter
func (acpc *AllClustersPropertyCollector) discoverAllClusters(ctx context.Context) ([]*mo.ClusterComputeResource, error) {
	log := logger.GetLogger(ctx)
	
	finder := find.NewFinder(acpc.vc.Client.Client, true)
	
	// Find all datacenters first
	datacenters, err := finder.DatacenterList(ctx, "*")
	if err != nil {
		return nil, fmt.Errorf("failed to list datacenters: %w", err)
	}
	
	var allClusters []*mo.ClusterComputeResource
	
	// Search for clusters in each datacenter
	for _, dc := range datacenters {
		finder.SetDatacenter(dc)
		
		clusters, err := finder.ClusterComputeResourceList(ctx, "*")
		if err != nil {
			log.Warnf("Failed to list clusters in datacenter %s: %v", dc.Name(), err)
			continue
		}
		
		for _, cluster := range clusters {
			clusterMo := &mo.ClusterComputeResource{}
			err := cluster.Properties(ctx, cluster.Reference(), []string{"name"}, clusterMo)
			if err != nil {
				log.Warnf("Failed to get properties for cluster %s: %v", cluster.Reference().Value, err)
				continue
			}
			
			allClusters = append(allClusters, clusterMo)
			log.Debugf("Discovered cluster: %s (%s)", clusterMo.Name, cluster.Reference().Value)
		}
	}
	
	log.Infof("Discovered %d clusters across %d datacenters", len(allClusters), len(datacenters))
	return allClusters, nil
}

// processAllClustersUpdates processes property updates for all clusters
func (acpc *AllClustersPropertyCollector) processAllClustersUpdates(ctx context.Context, updates []types.ObjectUpdate) {
	log := logger.GetLogger(ctx)
	log.Debugf("Processing %d property updates from all-clusters monitoring", len(updates))
	
	for _, update := range updates {
		objRef := update.Obj
		log.Debugf("Processing update for object: %s (%s)", objRef.Value, objRef.Type)
		
		switch objRef.Type {
		case "ClusterComputeResource":
			acpc.handleClusterUpdate(ctx, objRef, update.ChangeSet)
		case "HostSystem":
			acpc.handleHostUpdate(ctx, objRef, update.ChangeSet)
		default:
			log.Debugf("Ignoring update for unsupported object type: %s", objRef.Type)
		}
	}
}

// handleClusterUpdate processes ClusterComputeResource updates
func (acpc *AllClustersPropertyCollector) handleClusterUpdate(ctx context.Context, objRef types.ManagedObjectReference, changeSet []types.PropertyChange) {
	log := logger.GetLogger(ctx)
	clusterID := objRef.Value
	
	for _, change := range changeSet {
		switch change.Name {
		case "configuration.vsanConfig":
			acpc.handleClusterESAConfigChange(ctx, clusterID, change)
		case "host":
			acpc.handleClusterHostListChange(ctx, clusterID, change)
		default:
			log.Debugf("Ignoring cluster property change: %s", change.Name)
		}
	}
}

// handleHostUpdate processes HostSystem updates  
func (acpc *AllClustersPropertyCollector) handleHostUpdate(ctx context.Context, objRef types.ManagedObjectReference, changeSet []types.PropertyChange) {
	log := logger.GetLogger(ctx)
	hostID := objRef.Value
	
	for _, change := range changeSet {
		switch change.Name {
		case "config.product.version":
			acpc.handleHostVersionChange(ctx, hostID, change)
		case "datastore":
			acpc.handleHostDatastoreChange(ctx, hostID, change)
		default:
			log.Debugf("Ignoring host property change: %s", change.Name)
		}
	}
}

// handleClusterESAConfigChange handles vSAN ESA configuration changes (ONLY disabling)
func (acpc *AllClustersPropertyCollector) handleClusterESAConfigChange(ctx context.Context, clusterID string, change types.PropertyChange) {
	log := logger.GetLogger(ctx)
	
	if change.Val == nil {
		log.Infof("🚨 ESA config removed for cluster %s - calling OnClusterESADisabled", clusterID)
		// ESA disabled - this is a REMOVAL event we care about
		if acpc.actionHandlers.OnClusterESADisabled != nil {
			acpc.actionHandlers.OnClusterESADisabled(ctx, clusterID, []string{})
		}
		return
	}
	
	// Parse vSAN configuration to determine if ESA was disabled
	// We only care about ESA being disabled (removal event)
	log.Debugf("ESA configuration changed for cluster %s - checking if disabled", clusterID)
	
	// TODO: Parse actual ESA status from change.Val
	isESAEnabled := acpc.parseESAStatus(change.Val)
	
	if !isESAEnabled {
		// ESA was disabled - this is a REMOVAL event we care about
		log.Infof("🚨 ESA disabled for cluster %s - calling OnClusterESADisabled", clusterID)
		if acpc.actionHandlers.OnClusterESADisabled != nil {
			acpc.actionHandlers.OnClusterESADisabled(ctx, clusterID, []string{})
		}
	} else {
		// ESA was enabled - we don't care about addition events
		log.Debugf("ESA enabled for cluster %s - ignoring addition event", clusterID)
	}
}

// handleClusterHostListChange handles cluster host list changes (ONLY removals)
func (acpc *AllClustersPropertyCollector) handleClusterHostListChange(ctx context.Context, clusterID string, change types.PropertyChange) {
	log := logger.GetLogger(ctx)
	
	switch change.Op {
	case types.PropertyChangeOpAssign:
		// Full host list replacement - we need to determine what was removed
		log.Infof("Cluster %s host list replaced - checking for removed hosts", clusterID)
		// TODO: Compare with previous state to determine ONLY removed hosts
		// For now, we can't determine removals without caching previous state
		log.Debugf("Host list replacement detected but cannot determine removals without previous state cache")
		
	case types.PropertyChangeOpAdd:
		// Host added to cluster - we don't care about additions
		log.Debugf("Host added to cluster %s - ignoring addition event", clusterID)
		
	case types.PropertyChangeOpRemove:
		// Host removed from cluster - this is what we care about!
		log.Infof("🚨 Host removed from cluster %s - calling OnHostRemoved", clusterID)
		hostID := acpc.extractHostID(change.Val)
		if hostID != "" && acpc.actionHandlers.OnHostRemoved != nil {
			acpc.actionHandlers.OnHostRemoved(ctx, hostID, clusterID, []string{})
		}
	}
}

// handleHostVersionChange handles ESX host version changes (we don't care about version changes for removals)
func (acpc *AllClustersPropertyCollector) handleHostVersionChange(ctx context.Context, hostID string, change types.PropertyChange) {
	log := logger.GetLogger(ctx)
	
	// We only care about removal events, not version changes
	// Version changes don't represent infrastructure removal
	log.Debugf("Host %s version changed - ignoring since we only care about removal events", hostID)
}

// handleHostDatastoreChange handles host datastore mount changes (ONLY unmounts)
func (acpc *AllClustersPropertyCollector) handleHostDatastoreChange(ctx context.Context, hostID string, change types.PropertyChange) {
	log := logger.GetLogger(ctx)
	
	switch change.Op {
	case types.PropertyChangeOpAdd:
		// Datastore mounted on host - we don't care about additions
		log.Debugf("Datastore mounted on host %s - ignoring addition event", hostID)
		
	case types.PropertyChangeOpRemove:
		// Datastore unmounted from host - this is what we care about!
		datastoreID := acpc.extractDatastoreID(change.Val)
		log.Infof("🚨 Datastore %s unmounted from host %s - calling OnDatastoreUnmounted", datastoreID, hostID)
		if acpc.actionHandlers.OnDatastoreUnmounted != nil {
			acpc.actionHandlers.OnDatastoreUnmounted(ctx, datastoreID, hostID)
		}
		
	case types.PropertyChangeOpAssign:
		// Full datastore list replacement - we need to determine what was removed
		log.Debugf("Host %s datastore list replaced - would need previous state to determine removals", hostID)
		// TODO: Compare with previous state to determine ONLY unmounted datastores
	}
}

// Helper functions to extract IDs from property change values
func (acpc *AllClustersPropertyCollector) parseESAStatus(val interface{}) bool {
	// TODO: Implement actual ESA status parsing from vSAN config
	// This is a placeholder implementation
	return false
}

func (acpc *AllClustersPropertyCollector) extractHostID(val interface{}) string {
	// TODO: Extract host ID from ManagedObjectReference
	// This is a placeholder implementation
	if moref, ok := val.(types.ManagedObjectReference); ok {
		return moref.Value
	}
	return ""
}

func (acpc *AllClustersPropertyCollector) extractDatastoreID(val interface{}) string {
	// TODO: Extract datastore ID from ManagedObjectReference  
	// This is a placeholder implementation
	if moref, ok := val.(types.ManagedObjectReference); ok {
		return moref.Value
	}
	return ""
}


// =============================================================================
// DEFAULT PLACEHOLDER ACTION HANDLERS - REMOVAL EVENTS ONLY
// These are the functions that will be called when infrastructure REMOVAL occurs
// =============================================================================

// defaultOnHostRemoved is called when a host is removed from a cluster
func defaultOnHostRemoved(ctx context.Context, hostID string, clusterID string, affectedPolicies []string) {
	log := logger.GetLogger(ctx)
	log.Infof("🚨 HOST REMOVED: Host %s removed from cluster %s", hostID, clusterID)
	log.Infof("   📋 Affected policies: %v", affectedPolicies)
	log.Infof("   🔧 ACTION NEEDED: Remove host's datastores from topology of affected InfraSPI CRs")
	log.Infof("   🔧 ACTION NEEDED: Update LinkedClone/HighPerformanceLinkedClone capabilities")
	log.Infof("   🔧 ACTION NEEDED: Check if any policies become incompatible due to host removal")
	
	// TODO: Implement actual logic:
	// 1. Find all InfraSPI CRs that reference this host's datastores
	// 2. Remove this host's datastores from their topology
	// 3. Update capability flags based on remaining hosts
	// 4. Mark policies as incompatible if no compatible datastores remain
}


// defaultOnDatastoreUnmounted is called when a datastore is unmounted from ANY host
func defaultOnDatastoreUnmounted(ctx context.Context, datastoreID string, hostID string) {
	log := logger.GetLogger(ctx)
	log.Infof("🚨 DATASTORE UNMOUNTED: Datastore %s unmounted from host %s", datastoreID, hostID)
	log.Infof("   🔧 ACTION NEEDED: Update host-to-datastore mappings")
	log.Infof("   🔧 ACTION NEEDED: Recalculate topology for policies using this datastore")
	log.Infof("   💡 NOTE: Datastore might still be available on other hosts")
	
	// TODO: Implement actual logic:
	// 1. Update hostToDatastore cache (remove this specific host-datastore mapping)
	// 2. Find InfraSPI policies that reference this datastore
	// 3. Recalculate topology for affected policies
	//    - Check if datastore is still available in same AZ via other hosts
	//    - If not available in AZ, remove from policy topology for that AZ
	//    - If completely unavailable, mark policy as incompatible
	// 4. Update InfraSPI CR status if needed
}

// defaultOnClusterESADisabled is called when ESA is disabled on a cluster
func defaultOnClusterESADisabled(ctx context.Context, clusterID string, affectedPolicies []string) {
	log := logger.GetLogger(ctx)
	log.Infof("🚨 ESA DISABLED: Cluster %s disabled vSAN ESA", clusterID)
	log.Infof("   📋 Affected policies: %v", affectedPolicies)
	log.Infof("   🔧 ACTION NEEDED: Disable HighPerformanceLinkedClone for affected policies")
	log.Infof("   🔧 ACTION NEEDED: This is a capability REMOVAL event")
	
	// TODO: Implement actual logic:
	// 1. Find InfraSPI CRs that use this cluster's datastores  
	// 2. Set HighPerformanceLinkedClone = false (capability removed)
	// 3. Keep LinkedClone based on ESX version support (if still available)
	// 4. Update InfraSPI CR status to reflect capability removal
}