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

// InfrastructureEvent represents a vSphere infrastructure change event
type InfrastructureEvent struct {
	Type      EventType
	Source    string // e.g., "cluster", "host", "datastore"
	ObjectID  string
	Data      interface{}
	Timestamp int64
}

// EventType defines the type of infrastructure change (REMOVAL EVENTS ONLY)
type EventType string

const (
	// Active removal events that we monitor and handle
	EventTypeHostRemoved            EventType = "HostRemoved"
	EventTypeDatastoreUnmounted     EventType = "DatastoreUnmounted"
	EventTypeClusterESADisabled     EventType = "ClusterESADisabled"
	
	// Legacy events (kept for compatibility but not actively used)
	EventTypeHostAdded              EventType = "HostAdded"              // Not monitored
	EventTypeHostVersionChanged     EventType = "HostVersionChanged"     // Not monitored 
	EventTypeDatastoreAdded         EventType = "DatastoreAdded"         // Not monitored
	EventTypeDatastoreRemoved       EventType = "DatastoreRemoved"       // Not used (was too complex)
	EventTypeDatastoreMounted       EventType = "DatastoreMounted"       // Not monitored
	EventTypeClusterESAEnabled      EventType = "ClusterESAEnabled"      // Not monitored
	EventTypeClusterHostListChanged EventType = "ClusterHostListChanged" // Not monitored
)

// ClusterChangeEvent represents cluster-specific change details
type ClusterChangeEvent struct {
	ClusterID    string
	AddedHosts   []string
	RemovedHosts []string
	ESAEnabled   *bool // nil means no change
}

// AZEvent represents an Availability Zone change event
type AZEvent struct {
	Type     AZEventType
	ZoneName string
	Data     interface{}
}

// AZEventType defines the type of AZ change
type AZEventType string

const (
	AZEventTypeAdded   AZEventType = "Added"
	AZEventTypeRemoved AZEventType = "Removed"
	AZEventTypeUpdated AZEventType = "Updated"
)

// ESAConfig represents the ESA configuration state
type ESAConfig struct {
	Enabled       bool
	ClusterID     string
	Version       string
	Configuration map[string]interface{}
}

// DatastoreInfo represents datastore information
type DatastoreInfo struct {
	ID           string
	Name         string
	Type         string
	Accessible   bool
	Capacity     int64
	FreeSpace    int64
	URL          string
	InMaintMode  bool
}

// HostInfo represents host information
type HostInfo struct {
	ID            string
	Name          string
	ClusterID     string
	ESXVersion    string
	InMaintMode   bool
	Datastores    []string
	SupportsESA   bool
}

// ClusterInfo represents cluster information
type ClusterInfo struct {
	ID          string
	Name        string
	Hosts       []string
	ESAEnabled  bool
	VsanEnabled bool
}

// PolicyTopologyInfo represents topology information for a storage policy
type PolicyTopologyInfo struct {
	PolicyID              string
	PolicyName            string
	AccessibleZones       []string
	CompatibleDatastores  []string
	SupportsLinkedClone   bool
	SupportsHPLinkedClone bool
	TopologyType          string
}

// TopologyChangeRequest represents a request to update topology information
type TopologyChangeRequest struct {
	PolicyIDs             []string
	UpdateTopology        bool
	UpdateLinkedClone     bool
	UpdateHPLinkedClone   bool
	Reason                string
}