package admissionhandler

import (
	"context"
	"fmt"
	"reflect"

	vmoperatorv1alpha4 "github.com/vmware-tanzu/vm-operator/api/v1alpha4"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/vsphere-csi-driver/v3/pkg/common/utils"
	"sigs.k8s.io/vsphere-csi-driver/v3/pkg/csi/service/logger"
	k8s "sigs.k8s.io/vsphere-csi-driver/v3/pkg/kubernetes"

	"sigs.k8s.io/vsphere-csi-driver/v3/pkg/apis/cnsoperator/cnsfileaccessconfig/v1alpha1"
)

func setVmOwnerReference(
	ctx context.Context,
	cnsfileaccessconfig *v1alpha1.CnsFileAccessConfig) error {
	log := logger.GetLogger(ctx)

	if cnsfileaccessconfig.Spec.VMName == "" {
		return nil
	}

	restClientConfig, err := k8s.GetKubeConfig(ctx)
	if err != nil {
		msg := fmt.Sprintf("Failed to initialize rest clientconfig. Error: %+v", err)
		log.Error(msg)
		return err
	}

	vmOperatorClient, err := k8s.NewClientForGroup(ctx, restClientConfig, vmoperatorv1alpha4.GroupName)
	if err != nil {
		log.Error(fmt.Sprintf("Failed to initialize vmOperatorClient. Error: %+v", err))
		return err
	}

	vmName := cnsfileaccessconfig.Spec.VMName
	vm, err := getVmObject(ctx, vmOperatorClient, vmName, cnsfileaccessconfig.Namespace)
	if err != nil {
		log.Error(fmt.Sprintf("Failed to get vm object got VM %s. Error: %+v", vmName, err))
		return err
	}

	err = setVmOwnerReferenceUtil(ctx, *vm, cnsfileaccessconfig)
	if err != nil {
		log.Error(fmt.Sprintf("Failed to initialize vmOperatorClient. Error: %+v", err))
		return err
	}

	return nil
}

func getVmObject(ctx context.Context, vmOperatorClient client.Client,
	vmName string, namespace string) (*vmoperatorv1alpha4.VirtualMachine, error) {
	log := logger.GetLogger(ctx)
	vmKey := apitypes.NamespacedName{
		Namespace: namespace,
		Name:      vmName,
	}
	virtualMachine, err := utils.GetVirtualMachineAllApiVersions(ctx,
		vmKey, vmOperatorClient)
	if err != nil {
		log.Error(fmt.Sprintf("Failed to get virtualmachine instance for the VM with name: %q. Error: %+v", vmName, err))
		return nil, err
	}
	log.Infof("Successfully obtained VM object for VM %s", vmName)
	return virtualMachine, nil
}

func setVmOwnerReferenceUtil(ctx context.Context, vm vmoperatorv1alpha4.VirtualMachine, cnsfileaccessconfig *v1alpha1.CnsFileAccessConfig) error {
	if len(cnsfileaccessconfig.OwnerReferences) != 0 {
		for _, ownerRef := range cnsfileaccessconfig.OwnerReferences {
			if ownerRef.Kind == reflect.TypeOf(vmoperatorv1alpha4.VirtualMachine{}).Name() &&
				ownerRef.Name == cnsfileaccessconfig.Spec.VMName && ownerRef.UID == vm.UID {
				return nil
			}
		}
	}
	// Set ownerRef on CnsFileAccessConfig instance (in-memory) to VM instance.
	setInstanceOwnerRef(ctx, cnsfileaccessconfig, cnsfileaccessconfig.Spec.VMName, vm.UID)
	return nil
}

func setInstanceOwnerRef(ctx context.Context, cnsfileaccessconfig *v1alpha1.CnsFileAccessConfig, vmName string,
	vmUID apitypes.UID) {
	log := logger.GetLogger(ctx)
	bController := true
	bOwnerDeletion := true
	kind := reflect.TypeOf(vmoperatorv1alpha4.VirtualMachine{}).Name()
	cnsfileaccessconfig.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion:         "v1",
			Controller:         &bController,
			BlockOwnerDeletion: &bOwnerDeletion,
			Kind:               kind,
			Name:               vmName,
			UID:                vmUID,
		},
	}
	log.Infof("Successfully set owner reference for cnsFileAccessConfig CR %s to VM %s", cnsfileaccessconfig.Name, vmName)
}
