using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Tedd.HostMesh;
using Tedd.HostMesh.Agent;

return await HostProgram.Run(args);

internal static class HostProgram
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static async Task<int> Run(string[] args)
    {
        try
        {
            if (args is ["identity", var name, var folder]) { Identity(name, folder); return 0; }
            if (args is ["sign", var document, var authorityKey])
            {
                using var signer = X509CertificateLoader.LoadPkcs12FromFile(authorityKey, Secret("HOSTMESH_CERT_PASSWORD"));
                SignedConfiguration.Sign(document, signer);
                return 0;
            }
            if (args is not ["run", var file])
            {
                Console.Error.WriteLine("hostmesh identity <node-name> <directory> | hostmesh sign <document> <authority.pfx> | hostmesh run <node.json>");
                return 2;
            }
            string configPath = Path.GetFullPath(file);
            var authorityPath = Environment.GetEnvironmentVariable("HOSTMESH_AUTHORITY_CERT");
            using var authority = string.IsNullOrEmpty(authorityPath) ? null : X509CertificateLoader.LoadCertificateFromFile(authorityPath);
            var config = JsonSerializer.Deserialize<HostConfig>(SignedConfiguration.Read(configPath, authority), Json)
                ?? throw new InvalidDataException("Invalid configuration.");
            string Resolve(string path) => Path.GetFullPath(path, Path.GetDirectoryName(configPath)!);
            using var keys = new Certificates();
            var identity = keys.Add(X509CertificateLoader.LoadPkcs12FromFile(Resolve(config.PrivateKey),
                Secret(config.PasswordEnvironment), X509KeyStorageFlags.Exportable));
            var members = new MeshMembership(config.Members.Select(m => new Member(m.Id,
                keys.Add(X509CertificateLoader.LoadCertificateFromFile(Resolve(m.Certificate))), m.Relay, m.Ingress, Networks(m.Prefixes), m.RotationCertificates.Select(p => keys.Add(X509CertificateLoader.LoadCertificateFromFile(Resolve(p)))).ToArray())),
                config.Members.SelectMany(m => m.Addresses.Select(s => (Ip: IPAddress.Parse(s), m.Id))).ToDictionary(x => x.Ip, x => x.Id));
            var dials = config.Dial.ToDictionary(d => d.Node, d => IPEndPoint.Parse(d.Address));
            foreach (var peer in config.Discover)
            {
                if (peer == config.Node || dials.ContainsKey(peer)) continue;
                var member = config.Members.Single(m => m.Id == peer);
                if (member.Endpoint != null) dials.Add(peer, IPEndPoint.Parse(member.Endpoint));
            }
            var statePath = Resolve(config.StateDirectory);
            Directory.CreateDirectory(statePath);
            using var ownership = new FileStream(Path.Combine(statePath, "owner.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            var addresses = AddressReservations.Resolve(statePath, config.Applications.Select(a => (a.Name, a.Address)),
                members[config.Node].Prefixes ?? [], config.Members.SelectMany(m => m.Addresses.Select(IPAddress.Parse)), ip => members.Owner(ip) == config.Node);
            var grants = config.Applications.Select(app => new ApplicationGrant(app.Name, addresses[app.Name],
                app.Connect.Select(r => new DestinationRule(System.Net.IPNetwork.Parse(r.Network), r.Port)).ToArray(), app.ReportOrigin)).ToArray();
            var policy = new RevocationStore(statePath, config.PolicyFile == null ? null : Resolve(config.PolicyFile), config.Members.Select(m => m.Id), authority);
            long generation = NextGeneration(statePath);
            using var quit = new CancellationTokenSource();
            ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; quit.Cancel(); };
            Console.CancelKeyPress += cancel;
            using var term = OperatingSystem.IsWindows() ? null : PosixSignalRegistration.Create(PosixSignal.SIGTERM, c => { c.Cancel = true; quit.Cancel(); });
            try
            {
                var links = new QuiclyLinks(config.Node, members, identity,
                    config.Listen == null ? null : IPEndPoint.Parse(config.Listen), dials, config.AcceptFrom);
                await using var agent = await MeshAgent.StartAsync(config.Node, members, identity, links, grants,
                    TimeSpan.FromSeconds(config.OutageSeconds), quit.Token, generation, policy.Current.RevokedNodes);
                agent.Router.Conditions = new(config.BytesPerSecond, config.Loss);
                agent.Router.Preference = Enum.Parse<RoutingClass>(config.Routing, true);
                foreach (var (peer, cost) in config.LinkCosts) agent.Router.SetLinkCost(peer, cost);
                var forwards = new Stack<IAsyncDisposable>();
                try
                {
                    foreach (var app in config.Applications)
                    {
                        var local = agent.Register(app.Name);
                        if (app.Socket != null)
                        {
                            var path = Resolve(app.Socket);
                            var key = Convert.FromBase64String(Secret(app.KeyEnvironment ?? throw new InvalidDataException("Missing application key environment.")));
                            try { forwards.Push(LocalMeshServer.Listen(local, path, key, Networks(app.Accept))); }
                            finally { CryptographicOperations.ZeroMemory(key); }
                        }
                        foreach (var rule in app.Forwards)
                        {
                            var target = IPEndPoint.Parse(rule.Target);
                            var allow = Networks(rule.Allow);
                            forwards.Push(rule.Mode switch
                            {
                                "tcp-ingress" => local.ListenTcp(IPEndPoint.Parse(rule.Bind), target, allow),
                                "udp-ingress" => local.ListenUdp(IPEndPoint.Parse(rule.Bind), target, allow),
                                "tcp-target" => local.ForwardTcp(int.Parse(rule.Bind), target, allow),
                                "proxy-v2-target" => local.ForwardProxyTcp(int.Parse(rule.Bind), target, allow),
                                "udp-target" => local.ForwardUdp(int.Parse(rule.Bind), target, allow),
                                _ => throw new InvalidDataException("Unknown forwarding mode.")
                            });
                        }
                    }
                    Console.WriteLine($"Node {config.Node} ready. UDP listener {links.LocalEndPoint?.ToString() ?? "disabled"}.");
                    _ = Commands(agent, quit);
                    var settings = config.ConditionsFile == null ? null : Resolve(config.ConditionsFile);
                    string? previous = null;
                    using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(500));
                    try
                    {
                        while (await timer.WaitForNextTickAsync(quit.Token))
                        {
                            try
                            {
                                if (policy.Refresh()) await agent.SetRevokedNodesAsync(policy.Current.RevokedNodes);
                                if (settings == null || !File.Exists(settings)) continue;
                                var text = await File.ReadAllTextAsync(settings, quit.Token);
                                if (text == previous) continue;
                                var limits = JsonSerializer.Deserialize<Limits>(text, Json) ?? throw new JsonException();
                                agent.Router.Conditions = new(limits.BytesPerSecond, limits.Loss);
                                previous = text;
                            }
                            catch (Exception ex) when (ex is IOException or JsonException or ArgumentException or InvalidDataException or CryptographicException)
                            { Console.Error.WriteLine($"Configuration reload rejected: {ex.Message}"); }
                        }
                    }
                    catch (OperationCanceledException) when (quit.IsCancellationRequested) { }
                }
                finally { while (forwards.TryPop(out var item)) await item.DisposeAsync(); }
            }
            finally { Console.CancelKeyPress -= cancel; }
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex.Message); return 1; }
    }

    private static Task Commands(MeshAgent agent, CancellationTokenSource quit) => Task.Run(async () =>
    {
        while (!quit.IsCancellationRequested)
        {
            var line = await Console.In.ReadLineAsync();
            if (line == null) return;
            if (line == "stop") { quit.Cancel(); return; }
            if (line == "status") Console.WriteLine(JsonSerializer.Serialize(new { agent.Router.Routes, agent.Router.InteractiveRoutes, agent.Router.Conditions, agent.Router.Counters }, Json));
        }
    });

    private static long NextGeneration(string path)
    {
        string final = Path.Combine(path, "generation"), pending = final + ".next";
        long previous = File.Exists(final) ? long.Parse(File.ReadAllText(final)) : 0;
        long value = Math.Max(DateTimeOffset.UtcNow.UtcTicks, checked(previous + 1));
        using (var file = new FileStream(pending, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            file.Write(System.Text.Encoding.ASCII.GetBytes(value.ToString(System.Globalization.CultureInfo.InvariantCulture)));
            file.Flush(true);
        }
        File.Move(pending, final, true);
        return value;
    }

    private static System.Net.IPNetwork[] Networks(string[] rules) => rules.Select(System.Net.IPNetwork.Parse).ToArray();
    private static string Secret(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : throw new InvalidDataException($"Set {name}.");

    private static void Identity(string name, string directory)
    {
        var password = Secret("HOSTMESH_CERT_PASSWORD");
        if (name.Length == 0 || name.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')) throw new ArgumentException("Use letters, digits or hyphens in the node name.");
        Directory.CreateDirectory(directory);
        string pfx = Path.Combine(directory, name + ".pfx"), pub = Path.Combine(directory, name + ".cer");
        if (File.Exists(pfx) || File.Exists(pub)) throw new IOException("Identity files already exist.");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2")], false));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
        using var privateFile = new FileStream(pfx, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        privateFile.Write(cert.Export(X509ContentType.Pkcs12, password));
        using var publicFile = new FileStream(pub, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        publicFile.Write(cert.RawData);
    }

    private sealed class Certificates : IDisposable
    {
        private readonly List<X509Certificate2> _keys = [];
        public X509Certificate2 Add(X509Certificate2 key) { _keys.Add(key); return key; }
        public void Dispose() { foreach (var cert in _keys) cert.Dispose(); }
    }

    private sealed record HostConfig(ushort Node, string PrivateKey, MemberConfig[] Members, AppConfig[] Applications, DialConfig[] Dial)
    {
        public string PasswordEnvironment { get; init; } = "HOSTMESH_CERT_PASSWORD";
        public string? Listen { get; init; }
        public string Routing { get; init; } = "Throughput";
        public Dictionary<ushort, int> LinkCosts { get; init; } = [];
        public ushort[] AcceptFrom { get; init; } = [];
        public ushort[] Discover { get; init; } = [];
        public string StateDirectory { get; init; } = "hostmesh-state";
        public double OutageSeconds { get; init; } = 45;
        public string? ConditionsFile { get; init; }
        public string? PolicyFile { get; init; }
        public long BytesPerSecond { get; init; }
        public double Loss { get; init; }
    }
    private sealed record MemberConfig(ushort Id, string Certificate, string[] Addresses, bool Relay = false, bool Ingress = false)
    {
        public string[] Prefixes { get; init; } = [];
        public string? Endpoint { get; init; }
        public string[] RotationCertificates { get; init; } = [];
    }
    private sealed record DialConfig(ushort Node, string Address);
    private sealed record RuleConfig(string Network, int? Port = null);
    private sealed record ForwardConfig(string Mode, string Bind, string Target, string[] Allow);
    private sealed record AppConfig(string Name, string? Address, RuleConfig[] Connect)
    {
        public string? Socket { get; init; }
        public string? KeyEnvironment { get; init; }
        public string[] Accept { get; init; } = [];
        public bool ReportOrigin { get; init; }
        public ForwardConfig[] Forwards { get; init; } = [];
    }
    private sealed record Limits(long BytesPerSecond, double Loss);
}
