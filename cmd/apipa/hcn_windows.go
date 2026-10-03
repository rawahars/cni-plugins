package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	"golang.org/x/sys/windows"
)

// hcnAPI supplies shared switch, endpoint, and namespace operations for CNI requests.
type hcnAPI struct {
	networkByName      func(string) (*hcn.HostComputeNetwork, error)
	createNetwork      func(*hcn.HostComputeNetwork) (*hcn.HostComputeNetwork, error)
	endpointsOfNetwork func(string) ([]hcn.HostComputeEndpoint, error)
	endpointByName     func(string) (*hcn.HostComputeEndpoint, error)
	createEndpoint     func(*hcn.HostComputeEndpoint) (*hcn.HostComputeEndpoint, error)
	deleteEndpoint     func(*hcn.HostComputeEndpoint) error
	attach             func(string, string) error
	detach             func(string, string) error
	namespaceEndpoints func(string) ([]string, error)
}

// nativeAPI connects attachment operations to Windows networking with gateway suppression.
func nativeAPI() hcnAPI {
	// Create gateway-free endpoints separately from their later namespace attachment.
	return hcnAPI{
		networkByName: hcn.GetNetworkByName,
		createNetwork: func(n *hcn.HostComputeNetwork) (*hcn.HostComputeNetwork, error) {
			return n.Create()
		},
		endpointsOfNetwork: hcn.ListEndpointsOfNetwork,
		endpointByName:     hcn.GetEndpointByName,
		createEndpoint:     createGatewayFreeEndpoint,
		deleteEndpoint:     func(e *hcn.HostComputeEndpoint) error { return e.Delete() },
		attach:             hcn.AddNamespaceEndpoint,
		detach:             hcn.RemoveNamespaceEndpoint,
		namespaceEndpoints: hcn.GetNamespaceEndpointIds,
	}
}

// createGatewayFreeEndpoint creates an unattached link without an inherited gateway.
// Optional caller policies are applied before it can be attached.
func createGatewayFreeEndpoint(request *hcn.HostComputeEndpoint) (endpoint *hcn.HostComputeEndpoint, retErr error) {
	// Only a single-address, unattached request can bypass gateway inheritance.
	if len(request.IpConfigurations) != 1 || request.HostComputeNamespace != "" {
		return nil, errors.New("gateway-free creation requires one address and an unattached endpoint")
	}
	config := request.IpConfigurations[0]
	// Use HNS to suppress the subnet gateway without adding a synthetic default route.
	legacy := hcsshim.HNSEndpoint{
		Name: request.Name, VirtualNetwork: request.HostComputeNetwork,
		IPAddress: net.ParseIP(config.IpAddress), PrefixLength: config.PrefixLength,
		GatewayAddress: "0.0.0.0",
	}
	created, err := legacy.Create()
	if err != nil {
		return nil, fmt.Errorf("create gateway-free HNS endpoint: %w", err)
	}
	// Failed policy setup or readback removes only the new endpoint and preserves cleanup errors.
	defer func() {
		if retErr != nil {
			if _, err := created.Delete(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("roll back endpoint creation: %w", err))
			}
		}
	}()
	endpoint, err = hcn.GetEndpointByID(created.Id)
	if err != nil {
		return nil, fmt.Errorf("query created endpoint: %w", err)
	}
	if len(request.Policies) != 0 {
		if err := endpoint.ApplyPolicy(hcn.RequestTypeAdd, hcn.PolicyEndpointRequest{Policies: request.Policies}); err != nil {
			return nil, fmt.Errorf("apply configured endpoint policies: %w", err)
		}
		// Validate the live endpoint after native policies may have changed its settings.
		endpoint, err = hcn.GetEndpointByID(created.Id)
		if err != nil {
			return nil, fmt.Errorf("query configured endpoint: %w", err)
		}
	}
	return endpoint, nil
}

// withNetworkLock serializes operations on a shared switch across plugin processes.
// Acquisition, callback, and cleanup failures are returned to the caller.
func withNetworkLock(networkName string, fn func() error) (retErr error) {
	// Win32 mutex ownership belongs to the acquiring OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Case-insensitive switch names must share the same host-wide mutex.
	sum := sha256.Sum256([]byte(strings.ToLower(networkName)))
	name, err := windows.UTF16PtrFromString(`Global\apipa-cni-` + hex.EncodeToString(sum[:]))
	if err != nil {
		return fmt.Errorf("encode network mutex name: %w", err)
	}
	handle, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		return fmt.Errorf("create network mutex: %w", err)
	}
	// Handle cleanup errors remain visible alongside any protected operation failure.
	defer func() {
		if err := windows.CloseHandle(handle); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close network mutex: %w", err))
		}
	}()
	// Bound the wait to 30 seconds; an abandoned mutex still grants ownership.
	status, err := windows.WaitForSingleObject(handle, 30_000)
	if err != nil {
		return fmt.Errorf("wait for network mutex: %w", err)
	}
	if status != windows.WAIT_OBJECT_0 && status != windows.WAIT_ABANDONED {
		return fmt.Errorf("network mutex wait failed: status %#x", status)
	}
	defer func() {
		if err := windows.ReleaseMutex(handle); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("release network mutex: %w", err))
		}
	}()
	return fn()
}
