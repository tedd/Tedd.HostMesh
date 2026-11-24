using System.IO.Pipelines;
using System.Net;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;

namespace Tedd.HostMesh.AspNetCore;

/// <summary>A Kestrel endpoint on the configured local application's mesh IP.</summary>
public sealed class MeshHttpEndPoint(int port) : EndPoint
{
    public int Port { get; } = port is > 0 and <= 65535 ? port : throw new ArgumentOutOfRangeException(nameof(port));
    public override string ToString() => $"mesh:{Port}";
}

public static class MeshHttpTransport
{
    public static IServiceCollection AddHostMeshTransport(this IServiceCollection services, LocalMeshClient client) =>
        services.AddSingleton<IConnectionListenerFactory>(new Factory(client));

    private sealed class Factory(LocalMeshClient client) : IConnectionListenerFactory, IConnectionListenerFactorySelector
    {
        public bool CanBind(EndPoint endpoint) => endpoint is MeshHttpEndPoint;
        public async ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken token = default)
        {
            if (endpoint is not MeshHttpEndPoint mesh) throw new NotSupportedException("A mesh endpoint is required.");
            return new Listener(mesh, await client.ListenAsync(mesh.Port, token));
        }
    }

    private sealed class Listener(MeshHttpEndPoint endpoint, LocalMeshListener listener) : IConnectionListener
    {
        private readonly CancellationTokenSource _unbind = new();
        public EndPoint EndPoint => endpoint;
        public async ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default)
        {
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _unbind.Token);
            try { return new HttpConnection(await listener.AcceptAsync(stop.Token)); }
            catch (OperationCanceledException) when (_unbind.IsCancellationRequested) { return null; }
        }
        public ValueTask UnbindAsync(CancellationToken cancellationToken = default)
        {
            _unbind.Cancel(); listener.Dispose(); return ValueTask.CompletedTask;
        }
        public async ValueTask DisposeAsync() { await UnbindAsync(); _unbind.Dispose(); }
    }

    private sealed record Duplex(PipeReader Input, PipeWriter Output) : IDuplexPipe;

    private sealed class HttpConnection : DefaultConnectionContext
    {
        private readonly LocalMeshConnection _mesh;
        internal HttpConnection(LocalMeshConnection mesh)
        {
            _mesh = mesh;
            ConnectionId = Guid.NewGuid().ToString("N");
            LocalEndPoint = mesh.LocalEndPoint;
            RemoteEndPoint = mesh.Peer.EffectiveEndPoint;
            Features.Set(mesh.Peer);
            Transport = new Duplex(PipeReader.Create(mesh.Stream, new StreamPipeReaderOptions(leaveOpen: true)),
                PipeWriter.Create(mesh.Stream, new StreamPipeWriterOptions(leaveOpen: true)));
        }
        public override void Abort(ConnectionAbortedException reason) { _mesh.Dispose(); base.Abort(reason); }
        public override async ValueTask DisposeAsync()
        {
            try { await Transport.Output.CompleteAsync(); await Transport.Input.CompleteAsync(); }
            finally { _mesh.Dispose(); await base.DisposeAsync(); }
        }
    }
}
