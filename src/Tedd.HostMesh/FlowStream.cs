using System.Net.Quic;

namespace Tedd.HostMesh;

/// <summary>Serializes application writes and limits the size of each outstanding native send.</summary>
internal sealed class FlowStream(QuicStream stream) : Stream
{
    private readonly SemaphoreSlim _writes = new(1), _reads = new(1);
    private int _finished;
    public override bool CanRead => stream.CanRead;
    public override bool CanWrite => stream.CanWrite && Volatile.Read(ref _finished) == 0;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await _writes.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_finished != 0) throw new InvalidOperationException("Sending has finished.");
            while (!buffer.IsEmpty)
            {
                int count = Math.Min(32768, buffer.Length);
                await stream.WriteAsync(buffer[..count], cancellationToken).ConfigureAwait(false);
                buffer = buffer[count..];
            }
        }
        finally { _writes.Release(); }
    }
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await _reads.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false); }
        finally { _reads.Release(); }
    }
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken token) => WriteAsync(buffer.AsMemory(offset, count), token).AsTask();
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token) => ReadAsync(buffer.AsMemory(offset, count), token).AsTask();
    internal async ValueTask CompleteWritesAsync(CancellationToken token = default)
    {
        await _writes.WaitAsync(token).ConfigureAwait(false);
        try { if (Interlocked.Exchange(ref _finished, 1) == 0) stream.CompleteWrites(); }
        finally { _writes.Release(); }
    }
    internal void Abort() => stream.Abort(QuicAbortDirection.Both, 2);
    public override void Flush() => stream.Flush();
    public override Task FlushAsync(CancellationToken token) => stream.FlushAsync(token);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    protected override void Dispose(bool disposing) { if (disposing) stream.Dispose(); base.Dispose(disposing); }
    public override ValueTask DisposeAsync() => stream.DisposeAsync();
}
