using System.Net;
using static System.Buffers.Binary.BinaryPrimitives;

namespace Tedd.HostMesh.Tests;

public sealed class PacketTests
{
    [Theory]
    [InlineData(1)] [InlineData(833)] [InlineData(834)] [InlineData(835)] [InlineData(1200)]
    [InlineData(4096)] [InlineData(16384)] [InlineData(60000)] [InlineData(65507)]
    public void OutOfOrderFragmentsReassembleExactlyOnceDuringAnAssembly(int length)
    {
        var rng = new Random(length);
        byte[] expected = new byte[length];
        rng.NextBytes(expected);
        var frames = Enumerable.Range(0, (length + FragmentTable.Chunk - 1) / FragmentTable.Chunk)
            .Select(i => FragmentTable.Encode(1, 421, 17, expected, i)).OrderBy(_ => rng.Next()).ToArray();
        var table = new FragmentTable();
        for (int i = 0; i < frames.Length - 1; i++)
        {
            Assert.Null(table.Add(2, frames[i], 10, out _));
            Assert.Null(table.Add(2, frames[i], 20, out _));
        }
        Assert.Equal(expected, table.Add(2, frames[^1], 30, out var key));
        Assert.Equal(new PacketKey(2, 1, 421, 17), key);
        Assert.Equal(0, table.Count);
    }

    [Fact] public void StaleAndAbandonedFragmentsExpireAtBoundedCapacity()
    {
        var table = new FragmentTable();
        byte[] data = new byte[2000];
        for (uint seq = 1; seq <= 400; seq++) Assert.Null(table.Add(1, FragmentTable.Encode(1, 1, seq, data, 0), 10, out _));
        Assert.Equal(256, table.Count);
        table.Expire(3009);
        Assert.Equal(256, table.Count);
        table.Expire(3010);
        Assert.Equal(0, table.Count);
    }

    [Theory] [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    public void InvalidFragmentsDoNotPoisonValidAssembly(int corruption)
    {
        byte[] data = new byte[1200];
        var frame = FragmentTable.Encode(1, 4, 1, data, 0);
        switch (corruption)
        {
            case 0: frame[0] = 255; break;
            case 1: frame[15] = 200; break;
            case 2: WriteUInt16BigEndian(frame.AsSpan(13), 65535); break;
            case 3: frame = frame[..^1]; break;
            case 4: frame = frame[..8]; break;
        }
        var table = new FragmentTable();
        Assert.Null(table.Add(1, frame, 0, out _)); Assert.Equal(0, table.Count);
        Assert.Null(table.Add(1, FragmentTable.Encode(1, 4, 1, data, 0), 1, out _));
        Assert.Equal(data, table.Add(1, FragmentTable.Encode(1, 4, 1, data, 1), 2, out _));
    }

    [Fact] public void IndependentSourcesAndDirectionsCannotMixFragments()
    {
        var table = new FragmentTable();
        byte[] a = new byte[1200], b = Enumerable.Repeat((byte)22, 1200).ToArray();
        Assert.Null(table.Add(1, FragmentTable.Encode(1, 3, 4, a, 0), 1, out _));
        Assert.Null(table.Add(2, FragmentTable.Encode(1, 3, 4, b, 1), 1, out _));
        Assert.Null(table.Add(1, FragmentTable.Encode(2, 3, 4, b, 1), 1, out _));
        Assert.Equal(a, table.Add(1, FragmentTable.Encode(1, 3, 4, a, 1), 1, out _));
        Assert.Equal(2, table.Count);
    }

    [Theory] [InlineData("10.5.3.7", 0)] [InlineData("::1", 65535)] [InlineData("fd00::1234", 443)]
    public void MeshSourceAndPortSurviveWireEncoding(string ip, int port)
    {
        var expected = new IPEndPoint(IPAddress.Parse(ip), port);
        Span<byte> bytes = stackalloc byte[EndpointCodec.Size];
        EndpointCodec.Write(bytes, expected);
        Assert.Equal(expected, EndpointCodec.Read(bytes));
    }

    [Theory] [InlineData(0)] [InlineData(1)] [InlineData(65535)] [InlineData(1048576)]
    public async Task ReliableMessagesPreserveBoundariesAndEmptyPayloads(int length)
    {
        using var stream = new MemoryStream();
        byte[] data = new byte[length];
        new Random(42).NextBytes(data);
        await ReliableMessages.WriteAsync(stream, data);
        await ReliableMessages.WriteAsync(stream, new byte[] { 9 });
        stream.Position = 0;
        Assert.Equal(data, await ReliableMessages.ReadAsync(stream));
        Assert.Equal(new byte[] { 9 }, await ReliableMessages.ReadAsync(stream));
    }

    [Theory] [InlineData(-1)] [InlineData(1048577)] [InlineData(int.MaxValue)]
    public async Task InvalidLengthRejectedBeforeAllocation(int length)
    {
        byte[] header = new byte[4]; WriteInt32BigEndian(header, length);
        using var stream = new MemoryStream(header);
        await Assert.ThrowsAsync<InvalidDataException>(async () => await ReliableMessages.ReadAsync(stream));
    }

    [Fact] public async Task IncompleteReliableMessageFailsWithoutDeliveringAPrefix()
    {
        using var stream = new MemoryStream(new byte[] { 0, 0, 0, 4, 1, 2 });
        await Assert.ThrowsAsync<EndOfStreamException>(async () => await ReliableMessages.ReadAsync(stream));
    }
}
