using System.Diagnostics;
using System.Text;

namespace WsbMcp;

public sealed record WsbResult(int ExitCode, string Output, bool TimedOut);

/// <summary>Gateway to wsb.exe. Arguments are passed as an argv list, never through a shell.</summary>
public interface IWsbCli
{
    Task<WsbResult> RunAsync(IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken);

    /// <summary>
    /// Starts wsb.exe without redirected handles (for <c>connect</c>, which may spawn a
    /// long-lived window client) and waits up to <paramref name="wait"/> for it to exit.
    /// Returns the exit code, or null if it is still running.
    /// </summary>
    Task<int?> LaunchAsync(IReadOnlyList<string> arguments, TimeSpan wait, CancellationToken cancellationToken);
}

public sealed class WsbCli(string executable) : IWsbCli
{
    public async Task<WsbResult> RunAsync(IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        startInfo.ArgumentList.Add("--raw");
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        try
        {
            process.Start();
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            throw new ToolException($"Cannot start '{executable}': {ex.Message}");
        }
        process.StandardInput.Close();

        var stdout = process.StandardOutput.ReadToEndAsync(CancellationToken.None);
        var stderr = process.StandardError.ReadToEndAsync(CancellationToken.None);

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        var timedOut = false;
        try
        {
            await process.WaitForExitAsync(timeoutSource.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            timedOut = !cancellationToken.IsCancellationRequested;
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // Already exited.
            }
            await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            if (!timedOut)
            {
                throw;
            }
        }

        var output = (await stdout.ConfigureAwait(false) + await stderr.ConfigureAwait(false)).Trim();
        return new WsbResult(timedOut ? -1 : process.ExitCode, output, timedOut);
    }

    public async Task<int?> LaunchAsync(IReadOnlyList<string> arguments, TimeSpan wait, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("--raw");
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)
            ?? throw new ToolException($"Cannot start '{executable}'.");
        using var waitSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        waitSource.CancelAfter(wait);
        try
        {
            await process.WaitForExitAsync(waitSource.Token).ConfigureAwait(false);
            return process.ExitCode;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }
}
