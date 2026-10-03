package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/utils"
	"github.com/containernetworking/cni/pkg/version"
)

const (
	// defaultNetworkName identifies the shared switch when configuration omits a name.
	defaultNetworkName = "apipa-host"
	// subnetCIDR bounds the shared IPv4 link-local network.
	subnetCIDR = "169.254.0.0/16"
	// defaultHostAddress is the host peer address unless configuration overrides it.
	defaultHostAddress = "169.254.1.1"
	// internalNetwork selects a switch without an external adapter.
	// HCN supports it even though hcsshim does not expose a constant.
	internalNetwork hcn.NetworkType = "Internal"
)

// plugin handles APIPA lifecycle requests without changing primary container networking.
type plugin struct {
	api hcnAPI
}

// netConf carries CNI input and optional overrides for the shared host link.
type netConf struct {
	types.PluginConf
	// NetworkName selects the shared Windows switch, not the CNI configuration name.
	NetworkName string `json:"networkName,omitempty"`
	// HostAddress is the host peer address and is excluded from container allocation.
	HostAddress string `json:"hostAddress,omitempty"`
	// Policies are native endpoint settings applied only when an attachment is created.
	Policies []hcn.EndpointPolicy `json:"policies,omitempty"`
}

// loadConfig applies defaults and rejects unsupported CNI input before host changes.
func loadConfig(data []byte) (*netConf, error) {
	var conf netConf
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("decode CNI configuration: %w", err)
	}
	if conf.Type != "apipa" {
		return nil, fmt.Errorf("expected CNI type apipa, got %q", conf.Type)
	}
	switch conf.CNIVersion {
	case "0.4.0", "1.0.0":
	default:
		return nil, fmt.Errorf("unsupported CNI version %q; use 0.4.0 or 1.0.0", conf.CNIVersion)
	}
	// Keep the shared switch identity separate from the CNI attachment name.
	if err := utils.ValidateNetworkName(conf.Name); err != nil {
		return nil, fmt.Errorf("invalid CNI network name: %w", err)
	}
	if conf.NetworkName == "" {
		conf.NetworkName = defaultNetworkName
	}
	if err := utils.ValidateNetworkName(conf.NetworkName); err != nil {
		return nil, fmt.Errorf("invalid HCN network name: %w", err)
	}
	// The host peer must use the same usable link-local range as container addresses.
	if conf.HostAddress == "" {
		conf.HostAddress = defaultHostAddress
	}
	host, err := netip.ParseAddr(conf.HostAddress)
	if err != nil || !host.Is4() || !netip.MustParsePrefix(subnetCIDR).Contains(host) {
		return nil, fmt.Errorf("hostAddress must be an IPv4 link-local address, got %q", conf.HostAddress)
	}
	if octets := host.As4(); octets[2] == 0 || octets[2] == 255 {
		return nil, errors.New("hostAddress must not use an RFC 3927 reserved /24")
	}
	conf.HostAddress = host.String()
	// Reject external address management, DNS, and enabled capabilities before host changes.
	if conf.IPAM.Type != "" || !conf.DNS.IsEmpty() {
		return nil, errors.New("apipa manages its own addresses and does not configure DNS")
	}
	for capability, enabled := range conf.Capabilities {
		if enabled {
			return nil, fmt.Errorf("unsupported APIPA capability %q", capability)
		}
	}
	return &conf, nil
}

// previousResult converts and validates prior CNI output for safe chaining.
// It returns nil when the caller supplied no prior output.
func previousResult(conf *netConf) (*current.Result, error) {
	if conf.RawPrevResult == nil {
		return nil, nil
	}
	// Reject null entries before the shared CNI converters can dereference them.
	for _, field := range []string{"interfaces", "ips", "routes"} {
		if entries, ok := conf.RawPrevResult[field].([]any); ok {
			for _, entry := range entries {
				if entry == nil {
					return nil, fmt.Errorf("prevResult.%s contains a null entry", field)
				}
			}
		}
	}
	if err := version.ParsePrevResult(&conf.PluginConf); err != nil {
		return nil, fmt.Errorf("parse previous CNI result: %w", err)
	}
	result, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return nil, fmt.Errorf("convert previous CNI result: %w", err)
	}
	if err := validateResultStructure(result); err != nil {
		return nil, err
	}
	return result, nil
}

// validateArgs rejects invalid attachment IDs and requires a Windows namespace GUID.
// Cleanup may omit the namespace when it has already disappeared.
func validateArgs(args *skel.CmdArgs, requireNamespace bool) error {
	if err := utils.ValidateContainerID(args.ContainerID); err != nil {
		return fmt.Errorf("invalid container ID: %w", err)
	}
	if err := utils.ValidateInterfaceName(args.IfName); err != nil {
		return fmt.Errorf("invalid interface name: %w", err)
	}
	// Allow cleanup without a namespace, but reject filesystem paths and zero GUIDs.
	if args.Netns == "" && !requireNamespace {
		return nil
	}
	id, err := guid.FromString(args.Netns)
	if err != nil || id == (guid.GUID{}) {
		return fmt.Errorf("CNI_NETNS must identify a nonempty HCN namespace, got %q", args.Netns)
	}
	return nil
}

// endpointName returns a stable attachment key so retries reuse their endpoint.
func endpointName(conf *netConf, args *skel.CmdArgs) string {
	// Normalize the shared switch name while keeping CNI attachment identities distinct.
	sum := sha256.Sum256([]byte(strings.ToLower(conf.NetworkName) + "\x00" +
		conf.Name + "\x00" + args.ContainerID + "\x00" + args.IfName))
	return "apipa-" + hex.EncodeToString(sum[:])
}

// networkSpec requests a shared Internal switch with the configured host peer address.
// It disables automatic DNS without configuring traffic isolation.
func networkSpec(conf *netConf) *hcn.HostComputeNetwork {
	// The subnet gateway sets the host adapter address, not a container default route.
	return &hcn.HostComputeNetwork{
		Name: conf.NetworkName,
		Type: internalNetwork,
		Ipams: []hcn.Ipam{{
			Type: "Static",
			Subnets: []hcn.Subnet{{
				IpAddressPrefix: subnetCIDR,
				Routes: []hcn.Route{{
					DestinationPrefix: "0.0.0.0/0",
					NextHop:           conf.HostAddress,
				}},
			}},
		}},
		Policies: []hcn.NetworkPolicy{
			{Type: hcn.AutomaticDNS, Settings: json.RawMessage(`{"Enable":false}`)},
		},
		SchemaVersion: hcn.SchemaVersion{Major: 2},
	}
}

// validateNetwork rejects incompatible shared switches instead of modifying or adopting them.
func validateNetwork(network *hcn.HostComputeNetwork, conf *netConf) error {
	// HNS may mark a retained Internal switch nonpersistent across OS restarts.
	if network.Id == "" || !strings.EqualFold(network.Name, conf.NetworkName) || network.Type != internalNetwork ||
		network.Flags&^hcn.EnableNonPersistent != 0 {
		return fmt.Errorf("existing %s is not the expected Internal HCN network", conf.NetworkName)
	}
	// HCN omits Static, its zero-valued IPAM mode, in returned JSON.
	if len(network.Ipams) != 1 || (network.Ipams[0].Type != "" && network.Ipams[0].Type != "Static") ||
		len(network.Ipams[0].Subnets) != 1 {
		return fmt.Errorf("%s must have exactly one static IPv4 subnet", conf.NetworkName)
	}
	subnet := network.Ipams[0].Subnets[0]
	if subnet.IpAddressPrefix != subnetCIDR {
		return fmt.Errorf("%s has subnet %q, expected %s", conf.NetworkName, subnet.IpAddressPrefix, subnetCIDR)
	}
	// Verify the host peer without accepting additional routing or DNS settings.
	hasHostAddress := false
	for _, route := range subnet.Routes {
		switch {
		case route.DestinationPrefix == "0.0.0.0/0" && route.NextHop == conf.HostAddress:
			hasHostAddress = true
		case route.DestinationPrefix == subnetCIDR && (route.NextHop == "" || route.NextHop == "0.0.0.0"):
		default:
			return fmt.Errorf("%s has an unexpected subnet route %+v", conf.NetworkName, route)
		}
	}
	if !hasHostAddress || len(network.Dns.ServerList) != 0 || network.Dns.Domain != "" || len(network.Dns.Search) != 0 {
		return fmt.Errorf("%s must use host address %s and no DNS", conf.NetworkName, conf.HostAddress)
	}
	for _, policy := range network.Policies {
		if policy.Type != hcn.AutomaticDNS {
			continue
		}
		var settings hcn.AutomaticDNSNetworkPolicySetting
		if err := json.Unmarshal(policy.Settings, &settings); err != nil {
			return fmt.Errorf("decode network DNS policy: %w", err)
		}
		if settings.Enable {
			return fmt.Errorf("%s must not enable automatic DNS", conf.NetworkName)
		}
	}
	return nil
}

// ensureNetwork returns a compatible shared switch, creating it only when absent.
func (p plugin) ensureNetwork(conf *netConf) (*hcn.HostComputeNetwork, error) {
	// A lookup failure must not trigger replacement unless the switch is truly absent.
	network, err := p.api.networkByName(conf.NetworkName)
	if err != nil {
		if !hcn.IsNotFoundError(err) {
			return nil, fmt.Errorf("query APIPA network: %w", err)
		}
		network, err = p.api.createNetwork(networkSpec(conf))
		if err != nil {
			return nil, fmt.Errorf("create APIPA network: %w", err)
		}
	}
	// Both newly created and reused switches must satisfy the same requirements.
	if err := validateNetwork(network, conf); err != nil {
		return nil, err
	}
	return network, nil
}

// chooseAddress returns an unused link-local address, excluding the host and reserved ranges.
// It fails if existing allocations are invalid or the usable pool is exhausted.
func chooseAddress(seed uint32, endpoints []hcn.HostComputeEndpoint, hostAddress string) (string, error) {
	// Reserve the host and all live addresses before probing deterministic candidates.
	occupied := map[netip.Addr]bool{netip.MustParseAddr(hostAddress): true}
	for _, endpoint := range endpoints {
		for _, config := range endpoint.IpConfigurations {
			ip, err := netip.ParseAddr(config.IpAddress)
			if err != nil {
				return "", fmt.Errorf("endpoint %s has invalid address %q", endpoint.Id, config.IpAddress)
			}
			occupied[ip] = true
		}
	}
	// Wrap once through the pool, excluding the first and last /24 reserved by RFC 3927.
	const addresses = uint32(254 * 256)
	for offset := uint32(0); offset < addresses; offset++ {
		value := (seed%addresses + offset) % addresses
		ip := netip.AddrFrom4([4]byte{169, 254, byte(value/256 + 1), byte(value % 256)})
		if !occupied[ip] {
			return ip.String(), nil
		}
	}
	return "", errors.New("the APIPA address pool is exhausted")
}

// validateEndpoint rejects ownership, addressing, or routing drift.
// Unattached endpoints are allowed so ADD can validate before attaching.
func validateEndpoint(endpoint *hcn.HostComputeEndpoint, networkID, namespaceID, hostAddress string) error {
	if !strings.EqualFold(endpoint.HostComputeNetwork, networkID) || endpoint.Flags != hcn.EndpointFlagsNone {
		return errors.New("APIPA endpoint belongs to a different network or is a remote endpoint")
	}
	if endpoint.HostComputeNamespace != "" && !strings.EqualFold(endpoint.HostComputeNamespace, namespaceID) {
		return errors.New("APIPA endpoint belongs to a different namespace")
	}
	// Require one usable non-host address and a valid adapter identity.
	if len(endpoint.IpConfigurations) != 1 {
		return errors.New("APIPA endpoint must have exactly one IPv4 address")
	}
	config := endpoint.IpConfigurations[0]
	ip, err := netip.ParseAddr(config.IpAddress)
	if err != nil || !ip.Is4() || !netip.MustParsePrefix(subnetCIDR).Contains(ip) {
		return fmt.Errorf("invalid APIPA endpoint address %q", config.IpAddress)
	}
	octets := ip.As4()
	if config.PrefixLength != 16 || octets[2] == 0 || octets[2] == 255 || ip.String() == hostAddress {
		return fmt.Errorf("endpoint address %s/%d is not a usable APIPA address", ip, config.PrefixLength)
	}
	mac, err := net.ParseMAC(endpoint.MacAddress)
	if err != nil || len(mac) != 6 {
		return fmt.Errorf("invalid endpoint MAC address %q", endpoint.MacAddress)
	}
	// The guest adds its connected /16 route; HNS must not supply another default path.
	if len(endpoint.Routes) != 0 {
		return errors.New("APIPA endpoint must not contain inherited or synthetic routes")
	}
	return nil
}

// validateResultStructure rejects null entries and invalid interface references in prior output.
func validateResultStructure(result *current.Result) error {
	for _, iface := range result.Interfaces {
		if iface == nil {
			return errors.New("previous CNI result contains a null interface")
		}
	}
	// An address may omit its interface, but any supplied index must refer to a real entry.
	for _, ip := range result.IPs {
		if ip == nil {
			return errors.New("previous CNI result contains a null IP configuration")
		}
		if ip.Interface != nil && (*ip.Interface < 0 || *ip.Interface >= len(result.Interfaces)) {
			return fmt.Errorf("previous CNI result has invalid interface index %d", *ip.Interface)
		}
	}
	for _, route := range result.Routes {
		if route == nil {
			return errors.New("previous CNI result contains a null route")
		}
	}
	return nil
}

// endpointInResult reports whether prior output already describes this attachment.
// A matching address with a different adapter, namespace, prefix, or gateway is rejected.
func endpointInResult(result *current.Result, endpoint *hcn.HostComputeEndpoint, namespaceID string) (bool, error) {
	// Validate prior references before following address-to-interface links.
	if err := validateResultStructure(result); err != nil {
		return false, err
	}
	mac, err := net.ParseMAC(endpoint.MacAddress)
	if err != nil {
		return false, err
	}
	// The matching APIPA address must still identify the live adapter and namespace.
	for _, config := range result.IPs {
		if config.Address.IP.String() != endpoint.IpConfigurations[0].IpAddress {
			continue
		}
		bits, width := config.Address.Mask.Size()
		if config.Interface == nil || bits != 16 || width != 32 || config.Gateway != nil {
			return false, errors.New("previous result has an invalid APIPA IP configuration")
		}
		iface := result.Interfaces[*config.Interface]
		if !strings.EqualFold(iface.Mac, mac.String()) || !strings.EqualFold(iface.Sandbox, namespaceID) {
			return false, errors.New("previous APIPA result belongs to a different interface or namespace")
		}
		return true, nil
	}
	return false, nil
}

// appendEndpoint adds the APIPA link while preserving the caller's primary networking.
// Repeated merges do not duplicate the link or add a default gateway or DNS.
func appendEndpoint(previous *current.Result, endpoint *hcn.HostComputeEndpoint, args *skel.CmdArgs) (*current.Result, error) {
	result := &current.Result{CNIVersion: current.ImplementedSpecVersion}
	if previous != nil {
		*result = *previous
		result.CNIVersion = current.ImplementedSpecVersion
		// Appending must not mutate the earlier plugin's backing arrays.
		result.Interfaces = slices.Clone(previous.Interfaces)
		result.IPs = slices.Clone(previous.IPs)
		result.Routes = slices.Clone(previous.Routes)
		found, err := endpointInResult(result, endpoint, args.Netns)
		if err != nil {
			return nil, err
		}
		if found {
			return result, nil
		}
	}
	// Standalone calls use the requested interface; chained calls add a separate one.
	ifName := args.IfName
	if previous != nil {
		ifName = "apipa0"
	}
	for _, iface := range result.Interfaces {
		if iface.Name == ifName {
			return nil, fmt.Errorf("previous result already contains a different interface named %q", ifName)
		}
	}
	mac, err := net.ParseMAC(endpoint.MacAddress)
	if err != nil {
		return nil, err
	}
	index := len(result.Interfaces)
	result.Interfaces = append(result.Interfaces, &current.Interface{
		Name: ifName, Mac: mac.String(), Sandbox: args.Netns,
	})
	result.IPs = append(result.IPs, &current.IPConfig{
		Interface: &index,
		Address: net.IPNet{
			IP: net.ParseIP(endpoint.IpConfigurations[0].IpAddress).To4(), Mask: net.CIDRMask(16, 32),
		},
	})
	// Report the connected link-local route once without adding a default route.
	for _, route := range result.Routes {
		if route.Dst.String() == subnetCIDR && route.GW == nil {
			return result, nil
		}
	}
	_, subnet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return nil, err
	}
	result.Routes = append(result.Routes, &types.Route{Dst: *subnet})
	return result, nil
}

// removeEndpoint detaches and deletes this link, treating missing resources as cleaned up.
// Detach and delete failures are both returned; the shared switch is left intact.
func (p plugin) removeEndpoint(endpoint *hcn.HostComputeEndpoint) error {
	var detachErr error
	if endpoint.HostComputeNamespace != "" {
		detachErr = p.api.detach(endpoint.HostComputeNamespace, endpoint.Id)
		if hcn.IsNotFoundError(detachErr) {
			detachErr = nil
		}
		if detachErr != nil {
			detachErr = fmt.Errorf("detach APIPA endpoint: %w", detachErr)
		}
	}
	// Still attempt deletion after a detach failure, preserving both errors for the caller.
	deleteErr := p.api.deleteEndpoint(endpoint)
	if hcn.IsNotFoundError(deleteErr) {
		deleteErr = nil
	}
	if deleteErr != nil {
		deleteErr = fmt.Errorf("delete APIPA endpoint: %w", deleteErr)
	}
	return errors.Join(detachErr, deleteErr)
}

// add attaches a host-reachable link and writes CNI output without changing primary networking.
// On failure, rollback is limited to an endpoint created by this invocation.
func (p plugin) add(args *skel.CmdArgs) error {
	// Reject invalid input and malformed upstream output before acquiring shared resources.
	conf, err := loadConfig(args.StdinData)
	if err != nil {
		return err
	}
	if err := validateArgs(args, true); err != nil {
		return err
	}
	previous, err := previousResult(conf)
	if err != nil {
		return err
	}
	// Serialize switch reuse and address selection to prevent cross-process collisions.
	return withNetworkLock(conf.NetworkName, func() (retErr error) {
		network, err := p.ensureNetwork(conf)
		if err != nil {
			return err
		}
		// A retry reuses its endpoint instead of allocating another address.
		name := endpointName(conf, args)
		endpoint, err := p.api.endpointByName(name)
		created := false
		if err != nil {
			if !hcn.IsNotFoundError(err) {
				return fmt.Errorf("query APIPA endpoint: %w", err)
			}
			// Choose from live allocations before creating an unattached, gateway-free link.
			endpoints, err := p.api.endpointsOfNetwork(network.Id)
			if err != nil {
				return fmt.Errorf("list APIPA endpoints: %w", err)
			}
			sum := sha256.Sum256([]byte(name))
			address, err := chooseAddress(binary.BigEndian.Uint32(sum[:4]), endpoints, conf.HostAddress)
			if err != nil {
				return err
			}
			endpoint, err = p.api.createEndpoint(&hcn.HostComputeEndpoint{
				Name: name, HostComputeNetwork: network.Id,
				IpConfigurations: []hcn.IpConfig{{IpAddress: address, PrefixLength: 16}},
				Policies:         conf.Policies,
				SchemaVersion:    hcn.SchemaVersion{Major: 2},
			})
			if err != nil {
				return fmt.Errorf("create APIPA endpoint: %w", err)
			}
			created = true
		}
		// Native attachment can succeed before reporting an error; re-query before rollback.
		defer func() {
			if retErr != nil && created {
				owned, lookupErr := p.api.endpointByName(endpoint.Name)
				switch {
				case hcn.IsNotFoundError(lookupErr):
				case lookupErr != nil:
					retErr = errors.Join(retErr, fmt.Errorf("query endpoint during rollback: %w", lookupErr),
						p.removeEndpoint(endpoint))
				case !strings.EqualFold(owned.Id, endpoint.Id):
					retErr = errors.Join(retErr, errors.New("refusing to roll back a replacement endpoint"))
				case owned.HostComputeNamespace != "" && !strings.EqualFold(owned.HostComputeNamespace, args.Netns):
					retErr = errors.Join(retErr, errors.New("refusing to roll back an endpoint in another namespace"))
				default:
					retErr = errors.Join(retErr, p.removeEndpoint(owned))
				}
			}
		}()
		// Validate reused and new links before building output or attaching them.
		if err := validateEndpoint(endpoint, network.Id, args.Netns, conf.HostAddress); err != nil {
			return err
		}
		result, err := appendEndpoint(previous, endpoint, args)
		if err != nil {
			return err
		}
		// Attach only after endpoint and result validation; retries retain their attachment.
		if endpoint.HostComputeNamespace == "" {
			if err := p.api.attach(args.Netns, endpoint.Id); err != nil {
				return fmt.Errorf("attach APIPA endpoint to namespace: %w", err)
			}
			endpoint.HostComputeNamespace = args.Netns
		}
		// Confirm live namespace membership before emitting successful CNI output.
		ids, err := p.api.namespaceEndpoints(args.Netns)
		if err != nil {
			return fmt.Errorf("query HCN namespace endpoints: %w", err)
		}
		if !containsID(ids, endpoint.Id) {
			return errors.New("APIPA endpoint is not present in the target namespace")
		}
		return types.PrintResult(result, conf.CNIVersion)
	})
}

// containsID matches Windows resource GUIDs without depending on letter case.
func containsID(ids []string, id string) bool {
	for _, candidate := range ids {
		if strings.EqualFold(candidate, id) {
			return true
		}
	}
	return false
}

// del removes only this attachment's endpoint and retains the shared switch.
// Missing endpoints or an omitted namespace are valid during repeated cleanup.
func (p plugin) del(args *skel.CmdArgs) error {
	// Cleanup needs valid identity, but no prior output or live namespace.
	conf, err := loadConfig(args.StdinData)
	if err != nil {
		return err
	}
	if err := validateArgs(args, false); err != nil {
		return err
	}
	return withNetworkLock(conf.NetworkName, func() error {
		endpoint, err := p.api.endpointByName(endpointName(conf, args))
		if hcn.IsNotFoundError(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("query APIPA endpoint for deletion: %w", err)
		}
		// Prove switch and any supplied namespace ownership before deleting anything.
		network, err := p.api.networkByName(conf.NetworkName)
		if err != nil {
			return fmt.Errorf("query APIPA endpoint's network: %w", err)
		}
		if !strings.EqualFold(endpoint.HostComputeNetwork, network.Id) {
			return errors.New("refusing to delete an endpoint on a different network")
		}
		if args.Netns != "" && endpoint.HostComputeNamespace != "" &&
			!strings.EqualFold(endpoint.HostComputeNamespace, args.Netns) {
			return errors.New("refusing to delete an endpoint in a different namespace")
		}
		return p.removeEndpoint(endpoint)
	})
}

// check reports configuration or attachment drift without changing resources.
// The caller must supply prior output describing the live APIPA attachment.
func (p plugin) check(args *skel.CmdArgs) error {
	conf, err := loadConfig(args.StdinData)
	if err != nil {
		return err
	}
	if err := validateArgs(args, true); err != nil {
		return err
	}
	previous, err := previousResult(conf)
	if err != nil {
		return err
	}
	// CHECK must verify that the caller and host still describe the same link.
	if previous == nil {
		return errors.New("CHECK requires prevResult")
	}
	return withNetworkLock(conf.NetworkName, func() error {
		// Inspect live switch and endpoint settings without creating replacements.
		network, err := p.api.networkByName(conf.NetworkName)
		if err != nil {
			return fmt.Errorf("query APIPA network for CHECK: %w", err)
		}
		if err := validateNetwork(network, conf); err != nil {
			return err
		}
		endpoint, err := p.api.endpointByName(endpointName(conf, args))
		if err != nil {
			return fmt.Errorf("query APIPA endpoint for CHECK: %w", err)
		}
		if err := validateEndpoint(endpoint, network.Id, args.Netns, conf.HostAddress); err != nil {
			return err
		}
		// Confirm namespace membership and match the reported address to the live adapter.
		ids, err := p.api.namespaceEndpoints(args.Netns)
		if err != nil {
			return fmt.Errorf("query namespace for CHECK: %w", err)
		}
		if !strings.EqualFold(endpoint.HostComputeNamespace, args.Netns) || !containsID(ids, endpoint.Id) {
			return errors.New("APIPA endpoint is not attached to the requested namespace")
		}
		found, err := endpointInResult(previous, endpoint, args.Netns)
		if err != nil {
			return err
		}
		if !found {
			return errors.New("APIPA endpoint is missing from prevResult")
		}
		return nil
	})
}
