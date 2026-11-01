using System.IO.Pipes;
using System.Security.Principal;

namespace WsbMcp;

/// <summary>
/// Agent-side stdio bridge: forwards bytes between stdin/stdout and the broker pipe.
/// Contains no protocol logic; runs as the (untrusted) agent account.
/// </summary>
public static class Proxy
{
    public static async Task<int> RunAsync(string pipeName, int connectTimeoutMs, CancellationToken cancellationToken)
    {
        // Impersonation level lets the broker check folder access as this account.
        await using var pipe = new NamedPipeClientStream(
            ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation);
        try
        {
            await pipe.ConnectAsync(connectTimeoutMs, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            await Console.Error.WriteLineAsync(
                $"wsb-mcp proxy: broker pipe '\\\\.\\pipe\\{pipeName}' not available (broker not running or busy).")
                .ConfigureAwait(false);
            return 2;
        }

        await using var stdin = Console.OpenStandardInput();
        await using var stdout = Console.OpenStandardOutput();
        var upstream = CopyAsync(stdin, pipe, cancellationToken);
        var downstream = CopyAsync(pipe, stdout, cancellationToken);
        await Task.WhenAny(upstream, downstream).ConfigureAwait(false);
        return 0;
    }

    private static async Task CopyAsync(Stream source, Stream destination, CancellationToken cancellationToken)
    {
        var buffer = new byte[64 * 1024];
        try
        {
            int read;
            while ((read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (IOException)
        {
            // Peer closed; the other direction ends with it.
        }
        catch (OperationCanceledException)
        {
        }
    }
}
