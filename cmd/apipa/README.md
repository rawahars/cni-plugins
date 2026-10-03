# Windows APIPA CNI plugin

`apipa.exe` is a Windows CNI plugin for a host-reachable IPv4 link-local interface.
It works as a standalone plugin or as a chained plugin after an existing
primary network plugin. It is independent of any particular container
runtime, deployment layout, or primary plugin.

The APIPA interface can communicate with the host's configured link-local
address. There are no default traffic restrictions, and the plugin does
**not guarantee peer isolation**, even when native policies are accepted.
Networking through a container's other interfaces is unchanged.

## Requirements

- Windows with HNS/HCN v2 and the `Internal` network type.
- Administrator privileges for CNI execution.
- Go 1.23 or newer to build.
- A CNI-enabled runtime that supplies an HCN namespace GUID in `CNI_NETNS`.
- CNI configuration version `0.4.0` or `1.0.0`.

The supported deployment is Windows container networking. Linux network
namespace paths and Linux guest networking are not supported. The implementation uses
public `github.com/Microsoft/hcsshim` APIs and the standard CNI libraries.

## Configuration

The plugin accepts the standard CNI configuration fields and these options:

| Field | Default | Meaning |
| --- | --- | --- |
| `networkName` | `apipa-host` | Name of the shared HNS network to create/reuse |
| `hostAddress` | `169.254.1.1` | Host's IPv4 link-local address, without a prefix |
| `policies` | `[]` | Native HCN endpoint policy objects (`Type` and `Settings`), applied during endpoint creation |

The subnet is always `169.254.0.0/16`. The host address must be inside this
subnet and outside the RFC 3927 reserved first and last `/24`.
`name` is the CNI configuration name; it is distinct from `networkName`.

Each `policies` entry contains a native policy `Type` and its JSON `Settings`.
The plugin passes these to HCN without interpreting policy-specific settings.

A standalone configuration is provided in the
[standalone example](../../examples/standalone.conf):

```json
{
    "cniVersion": "0.4.0",
    "name": "example-apipa",
    "type": "apipa",
    "networkName": "apipa-host",
    "hostAddress": "169.254.1.1"
}
```

For chaining, insert the APIPA entry after your existing primary plugin in
a `.conflist`:

```json
{
    "cniVersion": "0.4.0",
    "name": "example-network",
    "plugins": [
        {
            "type": "YOUR_PRIMARY_PLUGIN"
        },
        {
            "type": "apipa",
            "networkName": "apipa-host",
            "hostAddress": "169.254.1.1"
        }
    ]
}
```

`YOUR_PRIMARY_PLUGIN` is a **placeholder**, not an included plugin. Replace
that object with your actual primary plugin's configuration, including its
required fields and capabilities. The template is also available as the
[chained example](../../examples/chained.conflist).

## Network and address management

The first network-creation step in ADD creates the configured shared
HNS network. Later ADDs reuse it. The network is an **Internal switch**
without an external physical adapter, with a host virtual adapter using
`hostAddress/16` and automatic DNS disabled.

The subnet's gateway setting establishes the host adapter address. It is
**not** exported as a container default gateway. HNS normally inherits this
gateway into endpoints. The plugin uses the public HNS endpoint API to
suppress that gateway without storing a synthetic zero-next-hop default
route. The live endpoint is read back and validated before attachment.
The Windows guest has its connected `169.254.0.0/16` route; the CNI result
adds no default route, gateway, or DNS.

HNS can populate the new guest adapter with the host's DNS servers/search
suffix even when empty DNS settings are requested. The plugin does not add
DNS to the CNI result or change the preceding plugin's DNS.

DEL retains the shared network across container lifecycles. HNS can mark
Internal networks nonpersistent across OS/service restarts; if the network
disappears, the next ADD recreates it with the same configured name and
host address.

Addresses are explicitly assigned and registered with HNS. These are managed
IPv4 link-local addresses, not guest DHCP fallback autoconfiguration.
Allocation excludes the host address, the RFC 3927 reserved first and last
`/24`, and addresses already assigned on the network.

A Windows named mutex, scoped by the HNS network name, serializes network
creation, address allocation, ADD, CHECK, and DEL across plugin processes.
No separate lease files or external IPAM plugin are needed.

Endpoint names are deterministic hashes of the HNS network name and CNI
attachment key: configuration name, container ID, and `CNI_IFNAME`. Repeating
ADD for the same attachment reuses its endpoint and address.

An existing network must match the configured type, subnet, host address,
flags, and DNS behavior. An incompatible object is rejected rather than
silently replaced. Keep configuration values consistent for a network's
lifetime. Avoid creating overlapping link-local switches on the same host;
multiple host routes to the same prefix require separate routing design.

## Connectivity and peer isolation

The Internal switch provides a shared link, not a peer-isolation boundary.
Endpoints on that switch may communicate directly. Support and enforcement
of supplied policies depend on the host HNS/HCN version and network
capabilities. Successful native policy application does not prove effective
traffic enforcement.

By default no endpoint policies are installed. Caller-supplied `policies`
are applied before attaching a newly created endpoint. A native policy
failure fails ADD and triggers rollback of that new endpoint; any cleanup
failure is reported alongside the original error.

Policies are creation-time settings. Repeated ADD reuses the existing
endpoint without reapplying, duplicating, or reconciling its policies, even
when configuration changes. Use DEL followed by ADD to recreate this
attachment with new policies. The shared network is retained.

The plugin does not configure VFP switch extensions or Windows Firewall.
Existing filtering settings are left unchanged when resources are reused.
CHECK validates addressing, routing, ownership, namespace membership, and
the prior result; it does not compare policies or prove enforcement.

If peer isolation is required, deploy and validate a separate host component
supported by the network, including any IPv6 link-local paths that must be
restricted. Caller policies must also preserve the gateway-free endpoint's
addressing and routing requirements.

A host service must listen on the configured host address, and host firewall
policy must permit the desired traffic. Any separate isolation component
must also preserve that host access. Other container interfaces remain
outside this plugin's scope.

## Chained results

- With `prevResult`, the plugin preserves existing interfaces, IP order,
  gateways, DNS, and routes, then appends an `apipa0` interface and its address.
  The preceding primary interface remains primary.
- Without `prevResult`, APIPA uses `CNI_IFNAME`, normally `eth0`, so standalone
  execution has a usable primary CNI result.
- No APIPA default route, gateway, or DNS is added to the result.
- Re-merging a result that already describes the same endpoint does not
  duplicate its interface.

`apipa0` is a CNI result name, not a guarantee about the Windows guest's
adapter friendly name. The guest may display it as `Ethernet 2`.

## Lifecycle and errors

| Command | Behavior |
| --- | --- |
| ADD | Create/reuse the network and endpoint, apply caller policies only for a new endpoint, validate ownership and addressing, attach to the supplied namespace, and return the merged result |
| CHECK | Validate network configuration, endpoint address/gateway suppression, namespace membership, and endpoint information in `prevResult`; do not create or repair resources |
| DEL | Detach/delete only this attachment's endpoint; retain the shared network |
| VERSION | Report CNI `0.4.0` and `1.0.0` support |

DEL is idempotent, does not require `prevResult`, and supports an empty
`CNI_NETNS` or a namespace that has already disappeared. It refuses to
delete an endpoint on another network or in another supplied namespace.

Failed ADD rolls back only an endpoint newly created by that invocation,
including a partially completed native attachment. Failed ADD and DEL
deliberately retain the shared network for future attachments.

External IPAM, DNS on the APIPA configuration, and additional capabilities
are rejected. Standard CNI JSON reports errors, including rollback failures.
Stdout is reserved for CNI protocol output.

## Build

From the [repository root](../../) in PowerShell:

```powershell
go test .\cmd\apipa
go vet .\cmd\apipa
go build -trimpath -o .\bin\apipa.exe .\cmd\apipa
```

For a versioned build:

```powershell
go build -trimpath -ldflags "-X main.pluginVersion=0.1.0" -o .\bin\apipa.exe .\cmd\apipa
```

Dependency checksums are recorded in [go.sum](../../go.sum). Generated executables are
ignored by Git.

## Install

Use your runtime's configured CNI binary and configuration directories.
For example, from an elevated PowerShell at the [repository root](../../):

```powershell
$binDir = "C:\cni\bin"
$confDir = "C:\cni\conf"
Copy-Item .\bin\apipa.exe (Join-Path $binDir "apipa.exe")
```

Back up any existing executable and active configuration before replacing
them. Add the APIPA entry to your actual primary configuration list, or
install the [standalone example](../../examples/standalone.conf) for standalone networking.

A plugin list must use `.conflist`, not `.conf`. Follow your runtime's
configuration-selection rules and ensure an older configuration does not
shadow the new one. Reload/restart the runtime as required and wait for its
network readiness signal before creating containers.

The first ADD creates the HNS network automatically. No manual network
creation is required. Installing the plugin does not retrofit interfaces
onto existing containers.

## Verify the deployment

Create a container using your runtime, then inspect the host:

```powershell
$networkName = "apipa-host"  # Match networkName in the active configuration.
$network = Get-HnsNetwork | Where-Object Name -eq $networkName
$network
Get-HnsEndpoint | Where-Object VirtualNetwork -eq $network.ID
Get-NetIPAddress -InterfaceAlias "vEthernet ($networkName)" -AddressFamily IPv4
```

Inside a Windows container:

```text
ipconfig
route print -4
```

For a chained configuration, expect the existing primary endpoint plus one
APIPA endpoint in the same HCN namespace. The existing primary IP and
default route should remain unchanged. The APIPA adapter must have a
link-local `/16` address and no default gateway.

For a meaningful connectivity test:

1. Run a service bound to the configured host address and allow its test port
   in the host firewall.
2. Create two containers using the [standalone example](../../examples/standalone.conf),
   so neither has an alternate network path.
3. Run a listening service on each container's APIPA address.
4. Confirm both containers reach the host service, and the host reaches their
   services.
5. Repeat with the chained configuration and verify its primary networking
   remains unchanged.

Peer traffic is unrestricted by default. If supplied policies or a separate
host component are intended to enforce isolation, additionally verify that
each container cannot reach the other's APIPA listener while host access
still works. Test IPv6 paths if applicable; ADD and CHECK are not enforcement
tests.

A failed connection to a nonexistent or unverified service does not prove
isolation. Remove temporary services and firewall rules after the test.

Use your runtime to delete test containers and namespaces. Their endpoints
should disappear while the shared network retains the same ID and host
address for the next attachment.

## Troubleshooting and removal

- **Network configuration not selected:** Check the file extension, active
  configuration order, runtime reload behavior, and executable location.
- **Incompatible existing network:** Inspect the configured HNS network.
  The plugin refuses incompatible objects rather than modifying them.
- **Unexpected APIPA gateway:** Inspect endpoint settings and the guest route
  table. ADD/CHECK reject a nonzero inherited default gateway. Host DNS
  appearing on the adapter is HNS inheritance, not added CNI-result DNS.
- **Host connection fails:** Verify the host adapter address, service binding,
  Windows Firewall, and any externally managed network filtering.
- **Peer connection succeeds:** This is expected without effective external
  enforcement. Verify that supplied policies are supported by the host network
  or inspect the separate isolation component, then test the APIPA destination
  specifically.

Delete containers created with this configuration before changing/removing
it: DEL must still be able to invoke the plugins that created their
endpoints. Restore the previous configuration and reload the runtime to
roll back.

The shared HNS network is retained deliberately. Only remove that specific
network after confirming no endpoints are using it.

## References

- [CNI specification](https://www.cni.dev/docs/spec/)
- [Host Compute Network API](https://learn.microsoft.com/virtualization/api/hcn/overview)
- [HcnCreateNetwork](https://learn.microsoft.com/virtualization/api/hcn/reference/hcncreatenetwork)
- [RFC 3927: IPv4 Link-Local Addressing](https://www.rfc-editor.org/rfc/rfc3927)
