# Tedd.HostMesh

Tedd.HostMesh connects .NET applications and TCP/UDP services over a private, routed network. Each host runs an agent. An application uses its own mesh IP and port through the SDK, or connects through a socket forward. A host behind NAT can initiate a connection to a relay and receive traffic over the same connection.

[Project website](https://tedd.no/Tedd.HostMesh/) · [Two-agent quickstart](#run-two-agents-on-loopback) · [.NET integration](#connect-a-net-application)

Use socket forwards to connect an existing service, or give a .NET application a mesh listener through the SDK. The mesh IP belongs to an application registered with an agent. A regular TCP client connects to the ingress socket on its host.

| Integration | Application entry point |
| --- | --- |
| Existing TCP or UDP service | A local ingress socket and a target forward at the backend |
| .NET application | `LocalMeshClient` over an authenticated local socket |
| ASP.NET Core or outbound HTTP | A Kestrel mesh listener or an `HttpClient` mesh handler |

## Run two agents on loopback

Use PowerShell 7, the .NET 10 SDK or later, a .NET 10 runtime with MsQuic support, and Python 3 for the sample HTTP backend. The example uses TCP ports 8443 and 9443 and UDP port 7300 on loopback. Start in the repository root.

```powershell
dotnet build Tedd.HostMesh.slnx
$demo = Join-Path ([System.IO.Path]::GetTempPath()) ("hostmesh-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $demo | Out-Null
Copy-Item examples/loopback/*.json $demo
$env:HOSTMESH_CERT_PASSWORD = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$agent = (Resolve-Path src/Tedd.HostMesh.Agent/bin/Debug/net10.0/Tedd.HostMesh.Agent.dll).Path
dotnet $agent identity edge $demo
dotnet $agent identity service $demo
```

Start a backend serving a single text file. Keep its document root separate from the certificates.

```powershell
$www = New-Item -ItemType Directory -Path (Join-Path $demo www)
Set-Content (Join-Path $www mesh.txt) 'Hello from Service'
$backend = Start-Process python -ArgumentList @('-m','http.server','9443','--bind','127.0.0.1') -WorkingDirectory $www.FullName -PassThru
```

From the same PowerShell window on Windows, launch the agents in separate consoles so each inherits the certificate password.

```powershell
$edge = Start-Process dotnet -ArgumentList @("`"$agent`"",'run','edge.json') -WorkingDirectory $demo -PassThru
$service = Start-Process dotnet -ArgumentList @("`"$agent`"",'run','service.json') -WorkingDirectory $demo -PassThru
```

Enter `status` in Edge’s console. Once its `routes` table shows node 2, make a request from the original shell.

```powershell
(Invoke-RestMethod http://127.0.0.1:8443/mesh.txt).Trim()
```

The expected response is `Hello from Service`. Edge accepts the TCP connection on port 8443 and opens a mesh stream to `10.84.2.10:443`. Service maps mesh port 443 to the HTTP backend at `127.0.0.1:9443`. Service initiates the QUIC link to Edge. Check the agent routes if the first request arrives before convergence. Enter `stop` in each agent console, then run `Stop-Process -Id $backend.Id`. The disposable directory in `$demo` contains both private keys. Remove it after the agents exit.

On Linux, run the backend and the two `dotnet <agent.dll> run <absolute-config-path>` commands in separate terminals. Supply the identity password in each agent’s environment. For deployment across hosts, provision each identity on its owner, distribute the public certificates, and replace the Edge listener and Service dial address with a reachable UDP endpoint.

## Routing and continuity

Neighbor agents exchange authenticated QUIC datagrams using Tedd.Quicly. Each node advertises its directed links and capacity, verifies signed link-state updates, and independently computes the next hop. Forwarding requires both neighbors to report the adjacency. A relay must have the relay role in the membership configuration.

Reliable streams run in a second, end-to-end QUIC connection between the two endpoint agents. Each endpoint keeps a stable local UDP socket for that connection. Relays forward the encapsulated packets according to their current routing tables. QUIC retains unacknowledged bytes, handles duplicates and reordering, and preserves stream offsets and half-closes through a route change. Endpoint restarts and partitions that exceed the connection's transport timeout terminate the stream.

The default throughput route favors the widest bottleneck, then the fewest hops. Latency routes minimize accumulated link delay plus configured administrative costs. Nodes use periodic heartbeats to discover silent failures. A graceful stop advertises a withdrawal. Native UDP preserves packet boundaries and permits loss. Applications that need reliable messages can use the length-prefixed `ReliableMessages` API over a mesh stream.

## Build and test

Use the .NET 10 SDK or later with the .NET 10 runtime and a supported MsQuic installation. Run from the repository directory.

```powershell
dotnet build Tedd.HostMesh.slnx
dotnet test tests/Tedd.HostMesh.Tests/Tedd.HostMesh.Tests.csproj
```

The suite includes a seeded virtual-time network, full-duplex streams over impaired links, and a four-process loopback deployment that kills and restarts a relay while a TCP backend connection stays open. Set `HOSTMESH_TEST_ROOT` to choose the parent directory for the process test's disposable configurations and certificates.

## Configure a mesh

Generate a separate identity on each host. Set `HOSTMESH_CERT_PASSWORD` in the agent environment to protect its private key. Copy the public `.cer` files to the participating hosts. Keep each `.pfx` on its owner. The agent trusts the configured membership files, so restrict writes to the configuration and identity directories.

```powershell
dotnet run --project src/Tedd.HostMesh.Agent -- identity edge .
```

This two-node example exposes a local TCP port on Edge and forwards it to a mesh listener on Service. Paths are relative to the node configuration. Both nodes need the same member identities and address grants.

```json
{
  "node": 1,
  "privateKey": "edge.pfx",
  "stateDirectory": "edge-state",
  "listen": "0.0.0.0:7300",
  "acceptFrom": [2],
  "dial": [],
  "conditionsFile": "edge-conditions.json",
  "members": [
    { "id": 1, "certificate": "edge.cer", "addresses": ["10.84.1.10"], "ingress": true, "relay": true },
    { "id": 2, "certificate": "service.cer", "addresses": ["10.84.2.10"] }
  ],
  "applications": [{
    "name": "edge", "address": "10.84.1.10", "reportOrigin": true,
    "connect": [{"network": "10.84.2.10/32", "port": 443}],
    "forwards": [{
      "mode": "tcp-ingress", "bind": "127.0.0.1:8443",
      "target": "10.84.2.10:443", "allow": ["127.0.0.0/8"]
    }]
  }]
}
```

For complete configurations and startup commands, see the [loopback example](examples/loopback) and the [quickstart](#run-two-agents-on-loopback). For additional permitted direct peers, include their node IDs in `discover` and a reachable UDP `endpoint` on their member entries. The agent attempts those adjacencies independently of its explicit `dial` seeds. Outbound-only nodes can leave their member endpoint unset.

On Service, generate `service.pfx` and `service.cer` using the identity command. Set `node` to `2`, `privateKey` to `service.pfx`, and use its own state directory. Omit `listen`, set `acceptFrom` to `[]`, and configure `dial` with Edge's reachable UDP endpoint. Use this application entry for a physical backend.

```json
{
  "name": "service",
  "address": "10.84.2.10",
  "connect": [],
  "forwards": [{
    "mode": "tcp-target", "bind": "443",
    "target": "127.0.0.1:9443", "allow": ["10.84.1.10/32"]
  }]
}
```

The physical backend must accept the socket before the mesh acknowledges the open. UDP uses `udp-ingress` and `udp-target`. Give the UDP target application an outgoing grant for the permitted client address range and return ports. Each client has a distinct reply association. TCP and UDP binds have independent port spaces.

For automatic application address assignment, delegate a unique CIDR in the member's `prefixes` array and omit the application's `address`. The agent records reservations by application name in its state directory. The first usable address is reserved for the host. IPv4 broadcast, explicitly assigned addresses, and existing reservations are excluded. Preserve the state directory across restarts.

To require signed node configurations and revocation updates, set `HOSTMESH_AUTHORITY_CERT` to a separately provisioned operator certificate. Use `dotnet run --project src/Tedd.HostMesh.Agent -- sign <document> <authority.pfx>` on the signing host, then distribute the document and its detached `.sig` together. Keep the signing private key off the mesh hosts.

To stage certificate rotation, add the replacement public certificate to the member's `rotationCertificates` array on participating hosts before switching the node's private key. Restart the owner with its replacement private key, then retire the previous pin from deployed membership. Endpoint restarts close that node's application streams.

For immediate revocation, configure `policyFile`, then write a policy such as `{"revision":1,"revokedNodes":[3]}` to each agent. The node withdraws affected routes and closes endpoint sessions. Higher revisions supersede earlier ones. The agent persists the last revision and its revoked set locally. Protect the policy file with the same permissions as the membership configuration.

## Connect a .NET application

Reference `Tedd.HostMesh`. Give the application a dedicated `socket` path, a `keyEnvironment` variable containing a base64-encoded 32-byte random secret, and `accept` CIDRs for incoming mesh connections. The local SDK and agent use an authenticated Unix-domain socket on Windows and Linux. Protect its parent directory and provide the application with only its own key.

```csharp
var mesh = new LocalMeshClient(socketPath, applicationKey);
using var listener = await mesh.ListenAsync(443, cancellationToken);
using var incoming = await listener.AcceptAsync(cancellationToken);
IPEndPoint client = incoming.Peer.EffectiveEndPoint;
await HandleRequestAsync(incoming.Stream, client, cancellationToken);
```

```csharp
using var connection = await mesh.ConnectAsync(
    new IPEndPoint(IPAddress.Parse("10.84.2.10"), 443), cancellationToken);
await ReliableMessages.WriteAsync(connection.Stream, request, cancellationToken);
connection.CompleteWrites();
byte[] response = await ReliableMessages.ReadAsync(connection.Stream, cancellationToken);
```

Use `BindDatagramAsync`, `SendToAsync` and `ReceiveAsync` for native UDP. An embedded host can use `MeshAgent.Register` and its in-process application API. Stream and datagram receivers can inspect the originating mesh endpoint, source node, and any external IP and port attested by an authorized ingress. A trusted gateway can call `LocalMeshClient.ConnectFromAsync` with the effective endpoint from its accepted connection. Its application must have `reportOrigin` permission on an ingress-authorized node. A physical socket backend sees its adjacent bridge as the TCP peer. For a compatible listener such as Nginx configured with `proxy_protocol`, use `proxy-v2-target` to send the effective client endpoint and mesh destination before the application byte stream.

For Kestrel, reference `Tedd.HostMesh.AspNetCore`, register `builder.Services.AddHostMeshTransport(mesh)`, and configure `builder.WebHost.ConfigureKestrel(k => k.Listen(new MeshHttpEndPoint(443)))`. Kestrel exposes the effective client IP in `HttpContext.Connection.RemoteIpAddress`. For outbound HTTP, pass `mesh.CreateHttpHandler()` to `HttpClient`. Supply a hostname-to-mesh-IP resolver when using named URLs.

## Change link conditions live

Set `conditionsFile` to a node-local JSON path and replace that file to change the node's aggregate mesh egress rate and independent packet-drop probability. The agent polls every 500 ms. Invalid updates retain the previous settings.

```json
{ "bytesPerSecond": 250000, "loss": 0.05 }
```

The rate counts mesh-record bytes, including mesh routing traffic. QUIC, UDP and IP headers add wire overhead. Zero bytes per second means unlimited. Loss ranges from zero to one. Changing the limits updates the node's advertised capacity and affects existing routed traffic. Embedded callers can assign `agent.Router.Conditions = new LinkConditions(250000, 0.05)`.

The limits apply to forwarded mesh records at the agent. Neighbor QUIC handshakes and acknowledgements generated by the hop carrier operate independently. A node can also use the seeded `SimulatedNetwork` to set directional reachability, serialization rate, latency, jitter, duplication and loss for individual links. A node accepts up to 28 advertised neighbors within a membership of up to 128 nodes. The application datagram payload limit is 60,000 bytes.

Use `"routing": "Latency"` to originate latency-class traffic. Set `"linkCosts": {"2": 25}` to add a 25 ms administrative cost to the link toward node 2. Enter `status` on the agent's standard input to inspect both forwarding tables, rate and loss settings, and packet counters. Enter `stop` for graceful withdrawal. Configure a second independently reachable relay for failover without waiting for the failed relay to return.
