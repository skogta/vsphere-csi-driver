/*
Datastore Removal vs Unmount Event Flow Explanation

This file demonstrates the difference between datastore unmount and removal events
and shows the typical event sequences you'll see.
*/

package topologywatcher

import (
	"context"
	"fmt"

	"sigs.k8s.io/vsphere-csi-driver/v3/pkg/csi/service/logger"
)

// DatastoreEventFlowExample demonstrates the event sequences
func DatastoreEventFlowExample() {
	fmt.Println(`
🎯 Datastore Event Flow: Unmount vs Removal

Scenario 1: Single Host Maintenance (UNMOUNT only)
================================================================
Initial State:
├── Datastore "shared-ds-001" mounted on:
│   ├── esxi-host-01 ✅
│   ├── esxi-host-02 ✅  
│   └── esxi-host-03 ✅

Admin puts esxi-host-02 in maintenance mode:
├── 🚨 Event: OnDatastoreUnmounted("shared-ds-001", "esxi-host-02")
├── Result: Datastore still available on esxi-host-01, esxi-host-03
└── InfraSPI Action: Recalculate topology (datastore might still be accessible in AZ)

Final State:
├── Datastore "shared-ds-001" mounted on:
│   ├── esxi-host-01 ✅
│   ├── esxi-host-02 ❌ (unmounted)
│   └── esxi-host-03 ✅

Scenario 2: Complete Datastore Deletion (UNMOUNT + REMOVAL)
================================================================
Initial State:
├── Datastore "temp-ds-002" mounted on:
│   ├── esxi-host-01 ✅
│   └── esxi-host-02 ✅

Admin deletes the datastore completely:
├── 🚨 Event 1: OnDatastoreUnmounted("temp-ds-002", "esxi-host-01")
├── 🚨 Event 2: OnDatastoreUnmounted("temp-ds-002", "esxi-host-02")  
├── 🚨 Event 3: OnDatastoreRemoved("temp-ds-002", "", ["policy-1", "policy-2"])
└── Result: Datastore completely gone from vCenter

Final State:
├── Datastore "temp-ds-002" ❌ (completely deleted)
└── InfraSPI Action: Remove from all policy topologies, mark policies as incompatible

Scenario 3: Datastore Network Partition (UNMOUNT from some hosts)
================================================================
Initial State:
├── Datastore "iscsi-ds-003" mounted on:
│   ├── esxi-host-01 ✅
│   ├── esxi-host-02 ✅
│   └── esxi-host-03 ✅

Network issue affects hosts 01 and 03:
├── 🚨 Event 1: OnDatastoreUnmounted("iscsi-ds-003", "esxi-host-01")
├── 🚨 Event 2: OnDatastoreUnmounted("iscsi-ds-003", "esxi-host-03")
├── Result: Datastore still available on esxi-host-02
└── InfraSPI Action: Recalculate topology (reduced availability)

Final State:
├── Datastore "iscsi-ds-003" mounted on:
│   ├── esxi-host-01 ❌ (network issue)
│   ├── esxi-host-02 ✅
│   └── esxi-host-03 ❌ (network issue)
	`)
}

// DatastoreEventDetectionLogic shows how to detect the difference
type DatastoreEventDetectionLogic struct {
	// Track which hosts have each datastore mounted
	datastoreHostMappings map[string]map[string]bool // datastoreID -> hostID -> mounted
}

// HandleDatastoreUnmountWithRemovalDetection shows enhanced logic
func (dedl *DatastoreEventDetectionLogic) HandleDatastoreUnmountWithRemovalDetection(
	ctx context.Context, 
	datastoreID, hostID string,
	handlers *InfrastructureActionHandlers,
) {
	log := logger.GetLogger(ctx)
	
	// 1. Handle the unmount event first
	log.Infof("🚨 Datastore %s unmounted from host %s", datastoreID, hostID)
	if handlers.OnDatastoreUnmounted != nil {
		handlers.OnDatastoreUnmounted(ctx, datastoreID, hostID)
	}
	
	// 2. Update our tracking
	if dedl.datastoreHostMappings == nil {
		dedl.datastoreHostMappings = make(map[string]map[string]bool)
	}
	if dedl.datastoreHostMappings[datastoreID] == nil {
		dedl.datastoreHostMappings[datastoreID] = make(map[string]bool)
	}
	dedl.datastoreHostMappings[datastoreID][hostID] = false // Mark as unmounted
	
	// 3. Check if datastore is now completely unmounted from all known hosts
	isCompletelyRemoved := dedl.isDatastoreCompletelyUnmounted(datastoreID)
	
	if isCompletelyRemoved {
		log.Infof("🚨 Datastore %s is now completely removed from all hosts", datastoreID)
		if handlers.OnDatastoreRemoved != nil {
			handlers.OnDatastoreRemoved(ctx, datastoreID, hostID, []string{})
		}
	} else {
		remainingHosts := dedl.getRemainingHostsForDatastore(datastoreID)
		log.Infof("Datastore %s still available on hosts: %v", datastoreID, remainingHosts)
	}
}

// isDatastoreCompletelyUnmounted checks if datastore has no remaining host mounts
func (dedl *DatastoreEventDetectionLogic) isDatastoreCompletelyUnmounted(datastoreID string) bool {
	hostMappings, exists := dedl.datastoreHostMappings[datastoreID]
	if !exists {
		return true // No mappings = completely unmounted
	}
	
	// Check if any host still has it mounted
	for _, mounted := range hostMappings {
		if mounted {
			return false // Still mounted on at least one host
		}
	}
	
	return true // No hosts have it mounted
}

// getRemainingHostsForDatastore returns list of hosts that still have the datastore
func (dedl *DatastoreEventDetectionLogic) getRemainingHostsForDatastore(datastoreID string) []string {
	var remainingHosts []string
	
	hostMappings, exists := dedl.datastoreHostMappings[datastoreID]
	if !exists {
		return remainingHosts
	}
	
	for hostID, mounted := range hostMappings {
		if mounted {
			remainingHosts = append(remainingHosts, hostID)
		}
	}
	
	return remainingHosts
}

// PropertyCollectorEventMapping shows what vSphere events map to our handlers
func PropertyCollectorEventMapping() {
	fmt.Println(`
🎯 vSphere Property Collector Event Mapping

HostSystem.datastore Property Changes:
=====================================
PropertyChangeOpRemove on specific datastore reference:
├── Maps to: OnDatastoreUnmounted(datastoreID, hostID)
├── Meaning: This host lost access to this datastore
└── Action: Update host-to-datastore cache, recalculate topology

PropertyChangeOpAssign (full list replacement):
├── Maps to: Compare old vs new list to detect unmounts
├── Meaning: Host's datastore list was completely replaced
└── Action: Detect which datastores were removed, call OnDatastoreUnmounted

Datastore Object Deletion (separate event):
├── Maps to: OnDatastoreRemoved(datastoreID, "", affectedPolicies)  
├── Meaning: Datastore object completely deleted from vCenter
└── Action: Remove from all policy topologies

Our Simplified Approach:
=======================
Since we only get HostSystem.datastore events (no Datastore object monitoring):

1. OnDatastoreUnmounted: Direct mapping from PropertyChangeOpRemove
2. OnDatastoreRemoved: Derived by tracking when datastore is unmounted from ALL hosts

This requires maintaining a cache of datastore-to-host mappings to detect 
when the last unmount occurs (which indicates complete removal).
	`)
}

// InfraSPIActionDifference shows different actions for unmount vs removal
func InfraSPIActionDifference() {
	fmt.Println(`
🎯 InfraSPI Action Differences: Unmount vs Removal

OnDatastoreUnmounted(datastoreID, hostID):
========================================
Scenario: Datastore unmounted from one host but might still be available on others

Actions:
├── 1. Update hostToDatastore cache (remove this specific mapping)
├── 2. Find InfraSPI policies that reference this datastore
├── 3. Check if datastore is still available in the same AZ (via other hosts)
├── 4. If still available: No topology change needed
├── 5. If not available in AZ: Remove from policy topology for that AZ
└── 6. Recalculate capabilities if needed

Example:
├── Policy "gold-policy" uses datastore "shared-nfs-01"  
├── "shared-nfs-01" unmounted from "esxi-03" 
├── "shared-nfs-01" still mounted on "esxi-01", "esxi-02"
└── Result: No topology change (datastore still accessible)

OnDatastoreRemoved(datastoreID, lastHostID, affectedPolicies):
============================================================
Scenario: Datastore completely removed from vCenter (no hosts have access)

Actions:
├── 1. Find ALL InfraSPI policies that reference this datastore
├── 2. Remove datastore from topology of ALL affected policies
├── 3. Recalculate all capabilities (LinkedClone, HighPerformanceLinkedClone)
├── 4. Check if any policies become completely incompatible
├── 5. Update InfraSPI status to reflect datastore removal
└── 6. Generate events/alerts for incompatible policies

Example:
├── Policy "platinum-policy" uses only datastore "fast-ssd-01"
├── "fast-ssd-01" completely removed from vCenter
├── Result: "platinum-policy" becomes incompatible (no valid datastores)
└── Action: Mark policy as incompatible, alert administrators

Critical Difference:
==================
├── Unmount: Datastore might still be usable (check other hosts)
├── Removal: Datastore is definitely unusable (immediate policy impact)
└── Different urgency levels and different InfraSPI update strategies
	`)
}