using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Tedd.HostMesh.AspNetCore;

namespace Tedd.HostMesh.Tests;

public sealed class ProcessMeshTests(Identities keys) : IClassFixture<Identities>
{
    private sealed class Child : IAsyncDisposable
    {
        private readonly Process _process;
        private readonly Task<string> _errors;
        internal Child(string file, string password, string appKey)
        {
            var start = new ProcessStartInfo("dotnet")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
            };
            start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "Tedd.HostMesh.Agent.dll"));
            start.ArgumentList.Add("run"); start.ArgumentList.Add(file);
            start.Environment.Remove("HOSTMESH_AUTHORITY_CERT");
            start.Environment["HOSTMESH_CERT_PASSWORD"] = password;
            start.Environment["MESH_TEST_APP_KEY"] = appKey;
            _process = Process.Start(start) ?? throw new IOException("Failed to start node.");
            _errors = _process.StandardError.ReadToEndAsync();
        }

        internal async Task Ready(CancellationToken ct)
        {
            var first = await _process.StandardOutput.ReadLineAsync(ct);
            if (first == null || !first.Contains("ready.")) throw new IOException("Node startup failed: " + await _errors.WaitAsync(ct));
        }

        internal async Task Route(int destination, int expected, CancellationToken ct)
        {
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                await _process.StandardInput.WriteLineAsync("status");
                var line = await _process.StandardOutput.ReadLineAsync(ct) ?? throw new IOException(await _errors);
                using var doc = JsonDocument.Parse(line);
                var routes = doc.RootElement.GetProperty("routes");
                if (routes.TryGetProperty(destination.ToString(), out var entry) && entry.GetProperty("nextHop").GetInt32() == expected) return;
                await Task.Delay(40, ct);
            }
        }

        internal async Task Crash(CancellationToken ct)
        {
            _process.Kill();
            await _process.WaitForExitAsync(ct);
        }

        internal async Task Stop(CancellationToken ct)
        {
            await _process.StandardInput.WriteLineAsync("stop");
            await _process.WaitForExitAsync(ct);
            Assert.True(_process.ExitCode == 0, await _errors);
        }

        public async ValueTask DisposeAsync()
        {
            if (!_process.HasExited)
            {
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(6));
                try { await Stop(deadline.Token); }
                catch (Exception ex) when (ex is OperationCanceledException or IOException)
                {
                    if (!_process.HasExited) _process.Kill();
                    await _process.WaitForExitAsync();
                }
            }
            await _errors;
            _process.Dispose();
        }
    }

    private static async Task RequestThroughKestrel(LocalMeshClient caller, LocalMeshClient service, CancellationToken ct)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.Services.AddHostMeshTransport(service);
        builder.WebHost.ConfigureKestrel(k => k.Listen(new MeshHttpEndPoint(9002)));
        await using var web = builder.Build();
        web.MapGet("/", (HttpContext request) => request.Connection.RemoteIpAddress!.ToString());
        await web.StartAsync(ct);
        try
        {
            using var http = new HttpClient(caller.CreateHttpHandler());
            Assert.Equal("10.80.0.1", await http.GetStringAsync("http://10.80.0.4:9002/", ct));
        }
        finally { await web.StopAsync(ct); }
    }

    private static int Port(bool udp)
    {
        using var s = new Socket(AddressFamily.InterNetwork, udp ? SocketType.Dgram : SocketType.Stream, udp ? ProtocolType.Udp : ProtocolType.Tcp);
        s.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)s.LocalEndPoint!).Port;
    }

    [Fact]
    public async Task FourProcessesKeepOneBackendSocketThroughLiveLimitsKillRestartAndWithdrawal()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(85));
        var ct = deadline.Token;
        string root = Environment.GetEnvironmentVariable("HOSTMESH_TEST_ROOT") ??
            (OperatingSystem.IsWindows() && Directory.Exists(@"D:\Workspaces\AI") ? @"D:\Workspaces\AI\hostmesh-tests" : Path.Combine(Path.GetTempPath(), "hostmesh-tests"));
        string dir = Directory.CreateDirectory(Path.Combine(Path.GetFullPath(root), "p-" + Guid.NewGuid().ToString("N")[..8])).FullName;
        string password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        byte[] appKey = RandomNumberGenerator.GetBytes(32);
        var children = new List<Child>();
        using var backend = new TcpListener(IPAddress.Loopback, 0);
        backend.Start();
        int backendPort = ((IPEndPoint)backend.LocalEndpoint).Port;
        int ingress = Port(false), relay2 = Port(true), relay3 = Port(true);
        while (relay2 == relay3) relay3 = Port(true);
        try
        {
            string AppSocket(int node) => Path.Combine(dir, "s" + node);
            string Config(int id) => Path.Combine(dir, id + ".json");
            for (int id = 1; id <= 4; id++)
            {
                File.WriteAllBytes(Path.Combine(dir, id + ".pfx"), keys.Keys[id].Export(X509ContentType.Pfx, password));
                File.WriteAllBytes(Path.Combine(dir, id + ".cer"), keys.Keys[id].RawData);
                object[] forwards = id switch
                {
                    1 => [new { mode = "tcp-ingress", bind = $"127.0.0.1:{ingress}", target = "10.80.0.4:4321", allow = new[] { "127.0.0.0/8" } }],
                    4 => [new { mode = "tcp-target", bind = "4321", target = $"127.0.0.1:{backendPort}", allow = new[] { "10.80.0.1/32" } }],
                    _ => []
                };
                var config = new
                {
                    node = id, privateKey = id + ".pfx", stateDirectory = "state" + id, conditionsFile = id + ".limits",
                    listen = id == 2 ? $"127.0.0.1:{relay2}" : id == 3 ? $"127.0.0.1:{relay3}" : null,
                    acceptFrom = id is 2 or 3 ? new[] { 1, 4 } : [], bytesPerSecond = id == 3 ? 128000 : 0,
                    dial = id is 1 or 4 ? new[] { new { node = 2, address = $"127.0.0.1:{relay2}" }, new { node = 3, address = $"127.0.0.1:{relay3}" } } : [],
                    members = Enumerable.Range(1, 4).Select(i => new { id = i, certificate = i + ".cer", addresses = new[] { Identities.Address((ushort)i).ToString() }, relay = i is 2 or 3, ingress = i == 1 }),
                    applications = id is 1 or 4 ? new[] { new { name = "app", address = Identities.Address((ushort)id).ToString(), reportOrigin = id == 1,
                        connect = new[] { new { network = "10.80.0.0/24" } }, accept = new[] { "10.80.0.0/24" }, socket = AppSocket(id), keyEnvironment = "MESH_TEST_APP_KEY", forwards } } : []
                };
                await File.WriteAllTextAsync(Config(id), JsonSerializer.Serialize(config), ct);
            }

            async Task<Child> Start(int id)
            {
                var c = new Child(Config(id), password, Convert.ToBase64String(appKey));
                children.Add(c); await c.Ready(ct); return c;
            }
            var b = await Start(2); var c = await Start(3); var a = await Start(1); var d = await Start(4);
            await a.Route(4, 2, ct); await d.Route(1, 2, ct);

            // Two independent application processes use the same agents via protected local IPC.
            var sdkA = new LocalMeshClient(AppSocket(1), appKey);
            var sdkD = new LocalMeshClient(AppSocket(4), appKey);
            var wrongKey = new LocalMeshClient(AppSocket(4), RandomNumberGenerator.GetBytes(32));
            await Assert.ThrowsAnyAsync<IOException>(() => wrongKey.ListenAsync(9002, ct));
            await RequestThroughKestrel(sdkA, sdkD, ct);
            using var listener = await sdkD.ListenAsync(9001, ct);
            using var sdkClient = await sdkA.ConnectAsync(new(Identities.Address(4), 9001), ct);
            using var sdkServer = await listener.AcceptAsync(ct);
            Assert.Equal(sdkClient.LocalEndPoint, sdkServer.Peer.EffectiveEndPoint);
            using var datagramClient = await sdkA.BindDatagramAsync(6100, ct);
            using var datagramServer = await sdkD.BindDatagramAsync(6101, ct);
            await datagramClient.SendToAsync(new(Identities.Address(4), 6101), new byte[] { 4, 2 }, ct);
            Assert.Equal(new byte[] { 4, 2 }, (await datagramServer.ReceiveAsync(ct)).Payload);

            using var external = new TcpClient();
            await external.ConnectAsync(IPAddress.Loopback, ingress, ct);
            using var accepted = await backend.AcceptTcpClientAsync(ct);
            var outside = external.GetStream(); var inside = accepted.GetStream();
            var rng = new Random(7841);
            async Task Check(Stream from, Stream to)
            {
                byte[] data = new byte[12288], actual = new byte[data.Length];
                rng.NextBytes(data); await from.WriteAsync(data, ct); await to.ReadExactlyAsync(actual, ct);
                Assert.Equal(data, actual);
            }
            await Check(outside, inside);
            await File.WriteAllTextAsync(Path.Combine(dir, "2.limits"), """{"bytesPerSecond":48000,"loss":0.08}""", ct);
            await a.Route(4, 3, ct); await Check(sdkClient.Stream, sdkServer.Stream);
            await File.WriteAllTextAsync(Path.Combine(dir, "2.limits"), """{"bytesPerSecond":0,"loss":0}""", ct);
            await a.Route(4, 2, ct);
            await b.Crash(ct);
            await Check(outside, inside); await a.Route(4, 3, ct);
            b = await Start(2); await a.Route(4, 2, ct);
            await c.Stop(ct); await Check(inside, outside);
            await Check(sdkServer.Stream, sdkClient.Stream);
            external.Client.Shutdown(SocketShutdown.Send);
            Assert.Equal(0, await inside.ReadAsync(new byte[1], ct));
            await Check(inside, outside);
            Assert.False(backend.Pending());
            await b.Stop(ct);
        }
        finally
        {
            foreach (var child in children.AsEnumerable().Reverse()) await child.DisposeAsync();
            if (Path.GetDirectoryName(dir) == Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar)
                && Path.GetFileName(dir).StartsWith("p-", StringComparison.Ordinal))
            {
                for (int attempt = 0; ; attempt++)
                {
                    try { Directory.Delete(dir, true); break; }
                    catch (IOException ex) when (OperatingSystem.IsWindows() && (ex.HResult & 0xffff) is 32 or 33 && attempt < 25)
                    { await Task.Delay(80); }
                }
            }
        }
    }
}
