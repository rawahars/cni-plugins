package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
)

const (
	// testNetworkID identifies the shared switch in simulated lifecycle requests.
	testNetworkID = "11111111-1111-1111-1111-111111111111"
	// testNamespaceID identifies the container namespace in valid test requests.
	testNamespaceID = "22222222-2222-2222-2222-222222222222"
)

// validEndpoint returns an attached, gateway-free link suitable as a valid test baseline.
func validEndpoint() *hcn.HostComputeEndpoint {
	return &hcn.HostComputeEndpoint{
		Id:                   "33333333-3333-3333-3333-333333333333",
		HostComputeNetwork:   testNetworkID,
		HostComputeNamespace: testNamespaceID,
		IpConfigurations:     []hcn.IpConfig{{IpAddress: "169.254.42.7", PrefixLength: 16}},
		MacAddress:           "02-00-00-00-00-01",
	}
}

// testArgs returns a standalone CNI request with valid attachment and namespace IDs.
func testArgs() *skel.CmdArgs {
	return &skel.CmdArgs{
		ContainerID: "test-pod", Netns: testNamespaceID, IfName: "eth0",
		StdinData: []byte(`{"cniVersion":"0.4.0","name":"test-network","type":"apipa"}`),
	}
}

// TestAppendEndpointPreservesPrimaryResult verifies that chaining preserves primary
// addressing, DNS, and routes without mutating the caller's prior output.
func TestAppendEndpointPreservesPrimaryResult(t *testing.T) {
	index := 0
	// Spare backing capacity exposes accidental in-place appends to upstream output.
	backing := make([]*current.Interface, 2)
	backing[0] = &current.Interface{Name: "eth0", Mac: "02:00:00:00:00:02"}
	_, defaultRoute, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		t.Fatal(err)
	}
	previous := &current.Result{
		CNIVersion: current.ImplementedSpecVersion,
		Interfaces: backing[:1],
		IPs: []*current.IPConfig{{
			Interface: &index,
			Address:   net.IPNet{IP: net.ParseIP("10.244.0.20").To4(), Mask: net.CIDRMask(24, 32)},
			Gateway:   net.ParseIP("10.244.0.1"),
		}},
		DNS:    types.DNS{Nameservers: []string{"10.0.0.1"}, Domain: "example.test"},
		Routes: []*types.Route{{Dst: *defaultRoute, GW: net.ParseIP("10.244.0.1")}},
	}
	// Snapshot prior output so both its contents and unused backing slot stay untouched.
	before, err := json.Marshal(previous)
	if err != nil {
		t.Fatal(err)
	}
	result, err := appendEndpoint(previous, validEndpoint(), testArgs())
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(previous)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) || backing[1] != nil {
		t.Fatal("merging the APIPA endpoint mutated prevResult or its backing array")
	}
	if len(result.Interfaces) != 2 || result.Interfaces[1].Name != "apipa0" || len(result.IPs) != 2 {
		t.Fatalf("unexpected merged interfaces/IPs: %+v", result)
	}
	if !reflect.DeepEqual(result.IPs[0], previous.IPs[0]) || !reflect.DeepEqual(result.DNS, previous.DNS) ||
		!reflect.DeepEqual(result.Routes[0], previous.Routes[0]) {
		t.Fatal("the primary IP, gateway, DNS, or route changed")
	}
	if *result.IPs[1].Interface != 1 || result.IPs[1].Gateway != nil || result.IPs[1].Address.String() != "169.254.42.7/16" {
		t.Fatalf("unexpected APIPA IP configuration: %+v", result.IPs[1])
	}
}

// TestAppendStandaloneAndRepeatedResult verifies the requested standalone interface
// and duplicate-free output when the same attachment is merged again.
func TestAppendStandaloneAndRepeatedResult(t *testing.T) {
	endpoint := validEndpoint()
	result, err := appendEndpoint(nil, endpoint, testArgs())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Interfaces) != 1 || result.Interfaces[0].Name != "eth0" || result.IPs[0].Gateway != nil {
		t.Fatalf("standalone APIPA did not use the default interface: %+v", result)
	}
	// Feed emitted output back in to model a retried attachment.
	repeated, err := appendEndpoint(result, endpoint, testArgs())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, repeated) {
		t.Fatal("repeated result merging duplicated or modified the APIPA interface")
	}
}

// TestPreviousResultRejectsMalformedEntries verifies that unsafe upstream entries
// are rejected rather than dereferenced during chaining.
func TestPreviousResultRejectsMalformedEntries(t *testing.T) {
	for _, previous := range []string{
		`{"cniVersion":"0.4.0","interfaces":[null]}`,
		`{"cniVersion":"0.4.0","ips":[null]}`,
		`{"cniVersion":"0.4.0","routes":[null]}`,
		`{"cniVersion":"0.4.0","interfaces":[{"name":"eth0"}],"ips":[{"version":"4","interface":-1,"address":"172.24.1.2/16"}]}`,
	} {
		t.Run(previous, func(t *testing.T) {
			// Keep the outer request valid so only the prior output is under test.
			data := []byte(`{"cniVersion":"0.4.0","name":"test-network","type":"apipa","prevResult":` + previous + `}`)
			conf, err := loadConfig(data)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := previousResult(conf); err == nil {
				t.Fatal("malformed prevResult was accepted")
			}
		})
	}
}

// TestChooseAddressAvoidsHostOccupiedAndReservedRanges verifies that allocation
// excludes the host, live addresses, and RFC 3927 reserved ranges.
func TestChooseAddressAvoidsHostOccupiedAndReservedRanges(t *testing.T) {
	endpoints := []hcn.HostComputeEndpoint{{
		Id: "existing", IpConfigurations: []hcn.IpConfig{
			{IpAddress: "169.254.1.0"}, {IpAddress: "169.254.1.2"},
		},
	}}
	address, err := chooseAddress(0, endpoints, defaultHostAddress)
	if err != nil {
		t.Fatal(err)
	}
	if address != "169.254.1.3" {
		t.Fatalf("allocator did not skip occupied addresses and the host: %s", address)
	}
	// Probe seeds that wrap around the pool so reserved ranges stay excluded.
	for _, seed := range []uint32{0, 1, 254*256 - 1, 254 * 256, ^uint32(0)} {
		address, err := chooseAddress(seed, nil, defaultHostAddress)
		if err != nil {
			t.Fatal(err)
		}
		octets := net.ParseIP(address).To4()
		if octets == nil || octets[2] == 0 || octets[2] == 255 || address == defaultHostAddress {
			t.Fatalf("allocator selected a reserved address: %s", address)
		}
	}
}

// TestEndpointValidationRejectsOwnershipAndRoutingDrift verifies that unsafe
// ownership, addressing, or routing changes are rejected.
func TestEndpointValidationRejectsOwnershipAndRoutingDrift(t *testing.T) {
	if err := validateEndpoint(validEndpoint(), testNetworkID, testNamespaceID, defaultHostAddress); err != nil {
		t.Fatalf("gateway-free endpoint was rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*hcn.HostComputeEndpoint)
	}{
		{"wrong network", func(e *hcn.HostComputeEndpoint) { e.HostComputeNetwork = "other" }},
		{"wrong namespace", func(e *hcn.HostComputeEndpoint) { e.HostComputeNamespace = "other" }},
		{"reserved APIPA range", func(e *hcn.HostComputeEndpoint) { e.IpConfigurations[0].IpAddress = "169.254.0.2" }},
		{"default route", func(e *hcn.HostComputeEndpoint) {
			e.Routes = append(e.Routes, hcn.Route{DestinationPrefix: "0.0.0.0/0", NextHop: defaultHostAddress})
		}},
		{"synthetic zero default", func(e *hcn.HostComputeEndpoint) {
			e.Routes = append(e.Routes, hcn.Route{DestinationPrefix: "0.0.0.0/0", NextHop: "0.0.0.0"})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Change one property at a time so every safety check must reject its drift.
			endpoint := validEndpoint()
			test.mutate(endpoint)
			if err := validateEndpoint(endpoint, testNetworkID, testNamespaceID, defaultHostAddress); err == nil {
				t.Fatal("unsafe endpoint state was accepted")
			}
		})
	}
}

// fakeHCN tracks shared networking state and injected failures without changing the host.
type fakeHCN struct {
	network         *hcn.HostComputeNetwork
	endpoints       map[string]*hcn.HostComputeEndpoint
	networkCreates  int
	endpointCreates int
	attachments     int
	detachments     int
	attachErr       error
	partialAttach   bool
	detachErr       error
	deleteErr       error
}

// api exposes in-memory networking operations with repeatable state and injectable failures.
func (f *fakeHCN) api() hcnAPI {
	// Keep state across calls to exercise retries and shared switch reuse.
	if f.endpoints == nil {
		f.endpoints = make(map[string]*hcn.HostComputeEndpoint)
	}
	return hcnAPI{
		networkByName: func(name string) (*hcn.HostComputeNetwork, error) {
			if f.network == nil {
				return nil, hcn.NetworkNotFoundError{NetworkName: name}
			}
			return f.network, nil
		},
		createNetwork: func(n *hcn.HostComputeNetwork) (*hcn.HostComputeNetwork, error) {
			n.Id = testNetworkID
			f.network = n
			f.networkCreates++
			return n, nil
		},
		endpointsOfNetwork: func(string) ([]hcn.HostComputeEndpoint, error) {
			var endpoints []hcn.HostComputeEndpoint
			for _, e := range f.endpoints {
				endpoints = append(endpoints, *e)
			}
			return endpoints, nil
		},
		endpointByName: func(name string) (*hcn.HostComputeEndpoint, error) {
			e, ok := f.endpoints[name]
			if !ok {
				return nil, hcn.EndpointNotFoundError{EndpointName: name}
			}
			// Return a snapshot so later attachment changes require a fresh lookup.
			copy := *e
			return &copy, nil
		},
		createEndpoint: func(e *hcn.HostComputeEndpoint) (*hcn.HostComputeEndpoint, error) {
			f.endpointCreates++
			e.Id = fmt.Sprintf("33333333-3333-3333-3333-%012d", f.endpointCreates)
			e.MacAddress = "02-00-00-00-00-01"
			copy := *e
			f.endpoints[e.Name] = &copy
			return e, nil
		},
		deleteEndpoint: func(e *hcn.HostComputeEndpoint) error {
			if f.deleteErr != nil {
				return f.deleteErr
			}
			delete(f.endpoints, e.Name)
			return nil
		},
		attach: func(namespace, id string) error {
			if f.attachErr != nil && !f.partialAttach {
				return f.attachErr
			}
			// A failed response may still follow a completed native attachment.
			f.attachments++
			for _, e := range f.endpoints {
				if e.Id == id {
					e.HostComputeNamespace = namespace
				}
			}
			return f.attachErr
		},
		detach: func(_, id string) error {
			f.detachments++
			if f.detachErr != nil {
				return f.detachErr
			}
			for _, e := range f.endpoints {
				if e.Id == id {
					e.HostComputeNamespace = ""
				}
			}
			return nil
		},
		namespaceEndpoints: func(namespace string) ([]string, error) {
			var ids []string
			for _, e := range f.endpoints {
				if e.HostComputeNamespace == namespace {
					ids = append(ids, e.Id)
				}
			}
			return ids, nil
		},
	}
}

// TestAddReusesNetworkAndEndpointAndDelRetainsNetwork verifies retry safety,
// distinct container addresses, and cleanup that retains shared resources.
func TestAddReusesNetworkAndEndpointAndDelRetainsNetwork(t *testing.T) {
	fake := &fakeHCN{}
	p := plugin{api: fake.api()}
	args := testArgs()
	if err := p.add(args); err != nil {
		t.Fatal(err)
	}
	var first hcn.HostComputeEndpoint
	for _, endpoint := range fake.endpoints {
		first = *endpoint
	}
	// Retry the same attachment before adding a different container namespace.
	if err := p.add(args); err != nil {
		t.Fatal(err)
	}
	if fake.networkCreates != 1 || fake.endpointCreates != 1 || fake.attachments != 1 {
		t.Fatal("repeated ADD recreated the network, endpoint, or attachment")
	}
	// A second container shares the switch but must receive its own address.
	secondPod := testArgs()
	secondPod.ContainerID = "second-pod"
	secondPod.Netns = "44444444-4444-4444-4444-444444444444"
	if err := p.add(secondPod); err != nil {
		t.Fatal(err)
	}
	if fake.networkCreates != 1 || len(fake.endpoints) != 2 {
		t.Fatal("a second pod did not reuse the shared network")
	}
	for _, endpoint := range fake.endpoints {
		if endpoint.Id != first.Id && endpoint.IpConfigurations[0].IpAddress == first.IpConfigurations[0].IpAddress {
			t.Fatal("different pods received the same APIPA address")
		}
	}
	// Repeated cleanup must leave the other container's endpoint and shared switch.
	if err := p.del(args); err != nil {
		t.Fatal(err)
	}
	if err := p.del(args); err != nil {
		t.Fatal(err)
	}
	if fake.network == nil || len(fake.endpoints) != 1 {
		t.Fatal("DEL removed the shared network or another pod's endpoint")
	}
}

// TestConfiguredPoliciesApplyOnlyOnCreation verifies native policy pass-through,
// duplicate-free retries, and configuration changes after endpoint recreation.
func TestConfiguredPoliciesApplyOnlyOnCreation(t *testing.T) {
	fake := &fakeHCN{}
	p := plugin{api: fake.api()}
	args := testArgs()
	settings := json.RawMessage(`{"Action":"Allow","Direction":"In","Protocols":"6","Priority":3000}`)
	args.StdinData = []byte(`{"cniVersion":"0.4.0","name":"test-network","type":"apipa","policies":[{"Type":"ACL","Settings":` + string(settings) + `}]}`)
	want := []hcn.EndpointPolicy{{Type: hcn.ACL, Settings: settings}}
	if err := p.add(args); err != nil {
		t.Fatal(err)
	}
	if err := p.add(args); err != nil {
		t.Fatal(err)
	}
	// Omitting policies on a retry must not replace the existing attachment's settings.
	args.StdinData = testArgs().StdinData
	if err := p.add(args); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range fake.endpoints {
		if !reflect.DeepEqual(endpoint.Policies, want) {
			t.Fatalf("configured policies were changed or duplicated: %+v", endpoint.Policies)
		}
	}
	if fake.endpointCreates != 1 || fake.attachments != 1 {
		t.Fatal("policy-bearing retries recreated or reattached the endpoint")
	}
	if err := p.del(args); err != nil {
		t.Fatal(err)
	}
	if err := p.add(args); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range fake.endpoints {
		if len(endpoint.Policies) != 0 {
			t.Fatal("recreated endpoint retained policies omitted from the new configuration")
		}
	}
}

// TestAddReturnsNativePolicyErrorWithoutAttaching verifies that native setup
// failures remain visible and cannot produce a successful namespace attachment.
func TestAddReturnsNativePolicyErrorWithoutAttaching(t *testing.T) {
	fake := &fakeHCN{}
	api := fake.api()
	createEndpoint := api.createEndpoint
	policyErr := errors.New("native endpoint policy rejected")
	api.createEndpoint = func(endpoint *hcn.HostComputeEndpoint) (*hcn.HostComputeEndpoint, error) {
		if len(endpoint.Policies) != 0 {
			return nil, policyErr
		}
		return createEndpoint(endpoint)
	}
	args := testArgs()
	args.StdinData = []byte(`{"cniVersion":"0.4.0","name":"test-network","type":"apipa","policies":[{"Type":"UnsupportedPolicy","Settings":{}}]}`)
	if err := (plugin{api: api}).add(args); !errors.Is(err, policyErr) {
		t.Fatalf("native policy failure was not reported: %v", err)
	}
	if fake.attachments != 0 || len(fake.endpoints) != 0 || fake.network == nil {
		t.Fatal("failed policy setup attached an endpoint or removed the shared network")
	}
}

// TestAddRollsBackAndReportsCleanupFailure verifies endpoint rollback after failed
// attachment and preserves both attachment and cleanup errors for the caller.
func TestAddRollsBackAndReportsCleanupFailure(t *testing.T) {
	attachErr := errors.New("attach failed")
	deleteErr := errors.New("delete failed")
	// Inject cleanup failure independently so neither error cause can hide the other.
	for _, failCleanup := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanup failure=%v", failCleanup), func(t *testing.T) {
			fake := &fakeHCN{attachErr: attachErr}
			if failCleanup {
				fake.deleteErr = deleteErr
			}
			p := plugin{api: fake.api()}
			err := p.add(testArgs())
			if !errors.Is(err, attachErr) {
				t.Fatalf("attachment failure was not preserved: %v", err)
			}
			if failCleanup {
				if !errors.Is(err, deleteErr) {
					t.Fatalf("cleanup failure was not reported: %v", err)
				}
			} else if len(fake.endpoints) != 0 {
				t.Fatal("failed ADD leaked its newly created endpoint")
			}
			if fake.network == nil {
				t.Fatal("failed ADD deleted the reusable shared network")
			}
		})
	}
}

// TestDelRefusesForeignNamespaceAndHandlesMissingNamespace verifies ownership
// protection and successful cleanup after the original namespace disappears.
func TestDelRefusesForeignNamespaceAndHandlesMissingNamespace(t *testing.T) {
	fake := &fakeHCN{}
	p := plugin{api: fake.api()}
	args := testArgs()
	if err := p.add(args); err != nil {
		t.Fatal(err)
	}

	// A caller supplying another namespace must not delete the existing attachment.
	foreign := *args
	foreign.Netns = "44444444-4444-4444-4444-444444444444"
	if err := p.del(&foreign); err == nil || len(fake.endpoints) != 1 {
		t.Fatal("DEL did not refuse a different namespace")
	}
	// Model namespace removal before DEL, without requiring the caller to retain its ID.
	fake.detachErr = hcn.NamespaceNotFoundError{NamespaceID: testNamespaceID}
	args.Netns = ""
	if err := p.del(args); err != nil || len(fake.endpoints) != 0 {
		t.Fatalf("DEL failed after the namespace disappeared: %v", err)
	}
}

// TestCheckDetectsRoutingDrift verifies that CHECK accepts a healthy attachment
// and reports an inherited default route without repairing it.
func TestCheckDetectsRoutingDrift(t *testing.T) {
	fake := &fakeHCN{}
	p := plugin{api: fake.api()}
	args := testArgs()
	if err := p.add(args); err != nil {
		t.Fatal(err)
	}
	var endpoint *hcn.HostComputeEndpoint
	for _, e := range fake.endpoints {
		endpoint = e
	}
	// Use emitted output as the caller's record of the expected attachment.
	result, err := appendEndpoint(nil, endpoint, args)
	if err != nil {
		t.Fatal(err)
	}
	converted, err := result.GetAsVersion("0.4.0")
	if err != nil {
		t.Fatal(err)
	}
	args.StdinData, err = json.Marshal(map[string]any{
		"cniVersion": "0.4.0", "name": "test-network", "type": "apipa", "prevResult": converted,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.check(args); err != nil {
		t.Fatal(err)
	}
	// Alter routing after a healthy CHECK to distinguish drift from setup errors.
	endpoint.Routes = []hcn.Route{{DestinationPrefix: "0.0.0.0/0", NextHop: defaultHostAddress}}
	if err := p.check(args); err == nil || !strings.Contains(err.Error(), "routes") {
		t.Fatalf("CHECK did not detect an inherited default route: %v", err)
	}
	if len(endpoint.Routes) != 1 || endpoint.Routes[0].NextHop != defaultHostAddress {
		t.Fatal("CHECK modified the endpoint's routes")
	}
}

// TestExistingIncompatibleNetworkIsNotReplaced verifies that ADD rejects an
// incompatible shared switch without modifying it or creating endpoints.
func TestExistingIncompatibleNetworkIsNotReplaced(t *testing.T) {
	conf, err := loadConfig(testArgs().StdinData)
	if err != nil {
		t.Fatal(err)
	}
	// Prepopulate a named switch with an incompatible type to rule out replacement.
	network := networkSpec(conf)
	network.Id = testNetworkID
	network.Type = hcn.Transparent
	fake := &fakeHCN{network: network}
	p := plugin{api: fake.api()}
	if err := p.add(testArgs()); err == nil {
		t.Fatal("an incompatible existing network was accepted")
	}

	if fake.networkCreates != 0 || len(fake.endpoints) != 0 || fake.network != network {
		t.Fatal("an incompatible existing network was modified")
	}
}

// TestNetworkAcceptsCanonicalHCNValues verifies that Windows-normalized
// switch properties remain compatible with the configured link.
func TestNetworkAcceptsCanonicalHCNValues(t *testing.T) {
	conf, err := loadConfig(testArgs().StdinData)
	if err != nil {
		t.Fatal(err)
	}
	network := networkSpec(conf)
	network.Id = testNetworkID
	// Model properties normalized by Windows rather than only the original request.
	network.Flags = hcn.EnableNonPersistent
	network.Ipams[0].Type = ""
	if err := validateNetwork(network, conf); err != nil {
		t.Fatalf("canonical HCN network properties were rejected: %v", err)
	}
}

// TestAddRollsBackPartialNativeAttachment verifies that failed ADD detaches and
// deletes a new endpoint even when native attachment completed before its error.
func TestAddRollsBackPartialNativeAttachment(t *testing.T) {
	attachErr := errors.New("native attach completed but its response failed")
	// Complete the simulated attachment before returning its error response.
	fake := &fakeHCN{attachErr: attachErr, partialAttach: true}
	p := plugin{api: fake.api()}
	if err := p.add(testArgs()); !errors.Is(err, attachErr) {
		t.Fatalf("partial attachment error was not preserved: %v", err)
	}
	if fake.detachments != 1 || len(fake.endpoints) != 0 {
		t.Fatal("rollback did not re-query and detach the partially attached endpoint")
	}
}

// TestCustomNetworkNameAndHostAddress verifies configured switch and host overrides,
// including host address reservation and endpoint validation.
func TestCustomNetworkNameAndHostAddress(t *testing.T) {
	fake := &fakeHCN{}
	p := plugin{api: fake.api()}
	args := testArgs()
	args.StdinData = []byte(`{"cniVersion":"1.0.0","name":"test-network","type":"apipa","networkName":"custom-host-link","hostAddress":"169.254.42.1"}`)
	if err := p.add(args); err != nil {
		t.Fatal(err)
	}
	if fake.network.Name != "custom-host-link" || fake.network.Ipams[0].Subnets[0].Routes[0].NextHop != "169.254.42.1" {
		t.Fatal("custom network name or host address was not used")
	}
	// The custom host peer remains reserved for the host.
	for _, endpoint := range fake.endpoints {
		if endpoint.IpConfigurations[0].IpAddress == "169.254.42.1" {
			t.Fatal("the configured host address was allocated to a pod")
		}
		if err := validateEndpoint(endpoint, testNetworkID, testNamespaceID, "169.254.42.1"); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRejectInvalidHostAddresses verifies rejection of malformed, non-IPv4,
// non-link-local, and RFC 3927 reserved host addresses.
func TestRejectInvalidHostAddresses(t *testing.T) {
	// Exercise syntactically valid but unusable addresses as well as malformed input.
	for _, address := range []string{"10.0.0.1", "169.254.0.1", "169.254.255.1", "fe80::1", "invalid"} {
		t.Run(address, func(t *testing.T) {
			data := []byte(fmt.Sprintf(`{"cniVersion":"1.0.0","name":"test-network","type":"apipa","hostAddress":%q}`, address))
			if _, err := loadConfig(data); err == nil {
				t.Fatal("an invalid or reserved host address was accepted")
			}
		})
	}
}
