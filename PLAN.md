# Tedd.HostMesh architecture and delivery plan

Tedd.HostMesh is a proposed private network for .NET applications and existing TCP/UDP services. Each host runs one agent. Each application can own a stable mesh IP and listen on its own ports. Agents maintain authenticated QUIC connections over UDP, deliver traffic directly when possible, and forward through authorized relays when necessary.

The first release is a userspace service overlay for Windows and Linux. A mesh IP is usable through the SDK or a configured socket forward. Ordinary OS-wide IP routing, ICMP, and transparent source addresses for arbitrary applications would require a separate virtual network interface and OS integration. The name **Tedd.HostMesh** describes the topology while leaving the transport and operating system open.

## A three-host deployment

The example uses an operator-selected private prefix. Physical listener addresses and mesh service addresses belong to separate address spaces.

| Host | Physical socket or SDK endpoint | Forwarding rule |
| --- | --- | --- |
| Edge | Public TCP `203.0.113.10:443` | Accept permitted clients and forward the TLS byte stream to `10.84.2.10:443` on Web. Record the observed client IP and source port. |
| Web | Nginx, mesh `10.84.2.10:443` | Deliver to Nginx on `127.0.0.1:8443`. A dedicated PROXY-protocol listener can receive the client address before TLS. |
| Data | MySQL, mesh `10.84.3.10:3306` | Deliver authorized database flows to `127.0.0.1:3306`. Allow the application and its explicitly authorized local client forward. |
| Web | .NET application, mesh `10.84.2.11` | Accept application traffic and connect to the database. A driver that opens its own socket can use a dedicated local forward. Give that forward its own restricted identity and authenticate local callers where identity matters. |

Nginx and the application can share a host while retaining distinct identities. If Web and Data cannot peer directly, Edge can carry their traffic when authorized for transit. That permission alone grants no right to open a database connection. Node roles can be combined or deployed independently.

## Address ownership, discovery, and policy

- Give each mesh a unique ID and trust root. A signed membership manifest assigns each stable node ID its certificate identity, exclusive address prefix, seed addresses, and allowed roles. Support operator-selected IPv4 and IPv6 pools. Validate prefix overlaps and conflicting physical binds before activation.
- Reserve one address per host. Allocate application addresses persistently from its prefix, with optional static reservations. An authenticated local registration binds an application ID to its permitted addresses and listeners. Two applications can use the same port on different IPs. A second owner of the same protocol/IP/port fails registration. After restart, a returning identity reclaims its reservation.
- Advertise prefixes by node and publish service records separately. An optional mesh-scoped name resolves to the service address through the agent. Version and expire records. During a partition, each host can allocate from its existing prefix. Moving ownership across hosts requires an authorized reassignment and fencing of the previous owner. Reserve service mobility and replicated service names for a later release.
- Grant separate permissions to bind a physical listener, originate a flow, relay a flow, and deliver it to a destination. Use source CIDRs at ingress and authenticated application or gateway identities plus destination protocol/address/port at egress. Deny unmatched rules. Restrict outgoing socket targets to explicit configured destinations. Validate a configuration revision as a unit and retain the last valid revision on reload.

## Transport and forwarding

Use the raw MsQuic carrier in Tedd.Quicly behind a small mesh transport adapter. Its public `ITransport` exposes bidirectional streams, datagrams, receive credit, send completions, and connection statistics. The higher-level `ReliableOrdered` game channel has a persistent stream per declared channel. A mesh with dynamic sockets needs independent flow control per connection. Pin a tested Quicly package version after exercising the carrier on both platforms. [Quicly transport contract](https://github.com/tedd/Tedd.Quicly/blob/2c506b0eaff0a308fd2d0a03c9362ba6146fb0be/src/Tedd.Quicly.Core/Transport/ITransport.cs) · [QUIC streams and flow control](https://www.rfc-editor.org/rfc/rfc9000.html#section-2)

| Traffic | Wire behavior | Application contract |
| --- | --- | --- |
| Routing and admission | A dedicated reliable control stream on each adjacency, with reserved processing and queue budgets | Version negotiation, membership, route advertisements, withdrawals, keepalives and diagnostics remain responsive under data load. |
| TCP or SDK stream | One bidirectional QUIC stream per flow per hop. Relay the bytes with backpressure in each direction. | Ordered bytes, independent half-close, cancellation, reset and bounded connect deadlines. Report success only after the destination listener or socket accepts the open. |
| Native UDP | QUIC DATAGRAM frames with a flow identifier and an admitted return association | Preserve message boundaries and reply mapping. Loss and reordering are permitted. Expire idle associations. Expose the smallest usable payload along the selected path, including mesh overhead. Report oversized SDK sends and count drops at socket bridges. |
| Reliable messages | Opt-in length-prefixed messages over a dedicated reliable stream | Preserve boundaries and order while connected. Both endpoints agree on the mode. A QUIC acknowledgement covers a hop. An application requiring proof of processing supplies an application acknowledgement. |

Use a mesh-specific ALPN and versioned bounded frames. A flow open carries its ID, endpoints, protocol, origin and selected node path. Relays validate transit policy, hop limit and adjacent peers, then allocate a local forwarding entry. Subsequent data uses that entry. Pool buffers, return receive credit as downstream capacity frees, and cap concurrent opens, queued bytes and UDP associations per application, peer and node. Bound pending opens and release application bytes only after the destination confirms the flow. [QUIC datagram size and delivery semantics](https://www.rfc-editor.org/rfc/rfc9221.html#section-5)

## Route selection and repair

1. **Form a sparse graph.** Start with several configured seed endpoints and outbound connections to at least two reachable relays where redundancy is required. Reuse a bidirectional adjacency for flows initiated from either side. Resolve simultaneous dials deterministically. Discover permitted direct neighbors and cap their number. An outbound-only node can serve inbound flows over a connection it initiated. If neither side can accept UDP, use a reachable relay. Networks that block all outbound UDP require a separate carrier.
2. **Distribute directed link state.** Each node advertises its own neighbor reachability, administrative cost, allowed transit classes, capacity cap, smoothed RTT, loss and estimated goodput. Authenticate the origin, use a persistent generation and increasing sequence, expire stale state, and reconcile snapshots after reconnection. Require recent confirmation at both ends before using an adjacency. Coalesce updates and refresh periodically.
3. **Apply policy before scoring.** Remove forbidden relays, unavailable links, paths over the hop limit and paths incompatible with the requested delivery mode. For interactive traffic, minimize cumulative delay with an administrative penalty. For bulk traffic, maximize the lowest usable link capacity on the path, then minimize delay. Cap measurements by configured capacity. An idle link has unknown capacity. Use a conservative configured estimate until traffic or a rate-limited probe supplies a sample. Use stable node IDs to break ties and prefer direct paths at comparable cost.
4. **Stabilize changes.** Smooth measurements over time, require a sustained improvement before switching the preferred path, and keep a warm alternate through a different relay when available. Pin open streams to their admitted path. On hard failure, invalidate the path immediately, reconnect peers with jittered backoff, and admit new flows over the best available path. Reject repeated node IDs during route setup and bound its lifetime. Peers can continue forwarding on valid cached state when seeds are offline.
5. **Specify established-flow behavior.** In the first release, a failed relay resets streams that used it. Return a typed path-loss error to the SDK and propagate a socket reset to TCP bridges. A surviving application reconnects. A bridge must never replay bytes or an ambiguous database write into a new backend connection. Native UDP may establish a fresh association and lose packets in flight. If uninterrupted sessions are required, add endpoint-owned flow state, per-direction offsets and acknowledgements, bounded retained bytes, authenticated resumption and duplicate suppression. Test this with the same live backend socket before promising continuity.

## .NET API and client address provenance

The proposed SDK opens one authenticated local session per application using a Windows named pipe or Unix domain socket. Map OS credentials to application identity. Applications sharing a service account need distinct credentials or service identities to obtain separate grants. The agent owns peer connections and routing independently of the application lifecycle.

| Proposed SDK operation | Result |
| --- | --- |
| `RegisterAsync(appId)` | Assigned mesh addresses, permissions and session lifetime. |
| `ListenAsync(localMeshEndpoint)` / `AcceptAsync()` | A listener and accepted duplex connections. Each exposes a .NET `Stream`, `CompleteWritesAsync`, local endpoint and verified peer context. |
| `ConnectAsync(destination, localAddress, cancellationToken)` | An outbound flow sourced from an address owned by the caller. Distinguish refusal, policy denial, no route, timeout and loss after establishment. |
| `BindDatagramAsync(localMeshEndpoint, deliveryMode)` | A message socket with `SendToAsync` and `ReceiveFromAsync`, origin metadata per association, cancellation and path payload limits. |

Expose the initiating mesh endpoint and principal, the external client endpoint observed by an authorized ingress when one exists, and the ID of the ingress node that attests to it. For an internal caller, the effective client IP is its assigned mesh address. For an external caller, it is the address the trusted ingress observed, which can be a NAT or upstream proxy. Have the ingress sign its assertion over the flow ID, observed address and port, destination, and expiry. The recipient checks the signature, ingress grant and freshness before accepting the asserted address. Ignore address claims from ordinary clients. Each new application connection starts a new origin context.

For ASP.NET Core, provide an optional Kestrel transport adapter exposing the effective remote endpoint and a feature containing provenance. For outbound HTTP over TCP, adapt the mesh stream to `SocketsHttpHandler.ConnectCallback`. A raw socket service normally sees its adjacent bridge. Supply PROXY protocol v2 only to dedicated, compatible listeners such as a configured Nginx endpoint. If Nginx creates a new HTTP request, use an explicitly trusted proxy chain for the HTTP client address. Database authentication continues to use the database protocol. [NGINX PROXY protocol](https://docs.nginx.com/nginx/admin-guide/load-balancer/using-proxy-protocol/) · [.NET HTTP connection callback](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.socketshttphandler.connectcallback)

## Trust and operations

Assume one administrative trust domain for the first release. Authenticate both nodes before routing or opening traffic. Verify mutual certificate support on the selected Quicly carrier as an implementation gate. If needed, extend the binding for mTLS before deployment. Bind node identity, mesh membership and roles to the authenticated session. Rotate certificates with an overlap window, persist revocation state, and close affected sessions on revocation. A partitioned node can enforce only the last revocation state it received. Credential and policy expiry bound that exposure.

Each relay terminates a QUIC hop and can read a plaintext application stream. Applications requiring confidentiality across relays can run their own TLS end to end, including Nginx TLS passthrough and MySQL TLS. Supporting untrusted third-party relays would require an authenticated endpoint-to-endpoint security layer for both streams and datagrams.

Expose peer status, reachability, selected path and reason, alternate path, last topology revision, route age, RTT, observed goodput, queue pressure, resets and UDP drops. Provide a route-explanation command that identifies the specific policy or link excluding a path. Audit registrations, ingress assertions and policy changes without recording payloads.

## Delivery sequence and acceptance

| Milestone | Deliverable | Acceptance gate |
| --- | --- | --- |
| 1. Two-host transport | Pin the carrier, prove mutual node authentication, independent streams, DATAGRAM support, return traffic over an outbound connection, and reconnect. Establish a direct-socket baseline. | Run against real MsQuic on Windows and Linux. A bulk sender cannot starve an independent echo stream or control traffic. Reject an unknown node. Measure CPU, memory, goodput and p99 latency under the same workload. |
| 2. Applications and bridges | Agent, persistent addresses, local SDK registration, TCP/UDP ingress and egress, policy, client provenance and reliable-message mode. | Two applications bind the same port on distinct IPs. Verify TCP half-close, UDP boundaries and replies, oversized sends, denied binds, source attribution, and an unchanged Nginx/MySQL deployment with a .NET client. |
| 3. Multi-hop routing | Authenticated topology advertisements, policy-aware path selection, warm alternates, and route explanations. | Use a four-node diamond and add or withdraw a direct edge to exercise direct, relayed and asymmetric paths. Remove the active relay during a transfer. Verify the existing stream reports loss, a new connection succeeds through the alternate, and no application bytes replay. Reject stale advertisements and prevent loops after a partition heals. |
| 4. Performance and operations | Capacity estimates, stable route preference, budgets, reload, certificate rotation, revocation and mixed-version negotiation. | Replay seeded loss, delay, reordering, bandwidth changes and restarts. Test one slow reader, noisy neighbors, fluctuating metrics, withdrawal and bounded memory. Publish measured hop overhead and recovery time. Start with a proposed lab goal of new connections succeeding within 5 seconds of a black-holed link when a healthy alternate already exists. |
| 5. Extensions selected by deployment need | Transparent live-stream resumption, NAT hole punching, service mobility, an OS virtual adapter, or an alternate carrier. | Give each feature a separate compatibility and fault test. For resumption, cut the path mid-request and prove byte continuity in both directions against the original backend connection. |

The reusable boundary is narrow. Adapt TcpTunnel's CIDR matching, socket binding, stream lifecycle, telemetry and tests while applying mesh policy defaults. Borrow TDFS's peer-pool ownership, jittered reconnect and deterministic fault scenarios. Use Quicly's simulated carrier for repeatable network failures and its real carrier for interoperability and measurements. TDFS consensus and storage can evolve independently of the mesh. [TcpTunnel stream contract](https://github.com/tedd/Tedd.TcpTunnel/blob/d97c3469266490dd825e0cac56e01614bb8d1fec/docs/api.md) · [TDFS peer pool](https://github.com/tedd/Tedd.TDFS/blob/f7532e1788fd3bfdbdad17a6e657d36e35bc2a27/src/Tedd.Tdfs.Server/Runtime/PeerConnections.cs) · [Quicly simulated carrier](https://github.com/tedd/Tedd.Quicly/tree/2c506b0eaff0a308fd2d0a03c9362ba6146fb0be/src/Tedd.Quicly.Testing/Simulation)

Before setting production targets, establish the expected node count, concurrent flows per host, largest UDP payload, deployment trust domains, and maximum interruption for active connections. Those determine the routing scale test, buffer budgets, datagram policy, and whether live resumption belongs in the first release.
