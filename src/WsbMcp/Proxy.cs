// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// https://github.com/fmuecke/windows-sandbox-mcp
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WsbMcp;

/// <summary>
/// Agent-side stdio bridge to the broker pipe; runs as the (untrusted) agent account and holds no
/// privilege. Online it forwards lines unchanged. Without a broker it answers the MCP handshake
/// itself and returns a hint from every tool call, reconnecting on each call (SPEC.md "Proxy").
/// </summary>
public sealed class Proxy(string pipeName, Stream clientInput, Stream clientOutput, TimeSpan connectTimeout)
{
    internal const string ReplayId = "wsb-mcp-proxy-replay";

    private static readonly JsonDocumentOptions ParseOptions = new() { MaxDepth = 32 };

    private readonly SemaphoreSlim _clientWrite = new(1, 1);
    private readonly object _sync = new();
    private readonly Dictionary<string, (JsonNode? Id, string Method)> _inFlight = [];
    private readonly ToolCatalog _offlineCatalog = ToolCatalog.Offline();
    private BrokerLink? _link;
    private string? _initializeLine;
    private bool _initialized;
    private string _lastFailure = "not connected yet";

    public static Task<int> RunAsync(string pipeName, CancellationToken cancellationToken) =>
        new Proxy(pipeName, Console.OpenStandardInput(), Console.OpenStandardOutput(), TimeSpan.FromSeconds(1))
            .RunAsync(cancellationToken);

    internal bool IsOnline => Volatile.Read(ref _link) is not null;

    public async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        var link = await TryConnectAsync(cancellationToken).ConfigureAwait(false);
        if (link is not null)
        {
            GoOnline(link);
        }

        var reader = new LineReader(clientInput, McpSession.MaxMessageBytes);
        while (true)
        {
            string? line;
            try
            {
                line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidDataException)
            {
                return 1; // Oversized message from the client: cannot resynchronize.
            }
            catch (OperationCanceledException)
            {
                break;
            }
            if (line is null)
            {
                break;
            }
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }
            await HandleClientLineAsync(line, cancellationToken).ConfigureAwait(false);
        }

        // Client closed its side: let pending broker responses through before exiting.
        await DrainAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
        Volatile.Read(ref _link)?.Dispose();
        return 0;
    }

    private async Task HandleClientLineAsync(string line, CancellationToken cancellationToken)
    {
        var message = Parse(line);
        var method = message?["method"] is JsonValue m && m.GetValueKind() == JsonValueKind.String ? m.GetValue<string>() : null;
        var hasId = message?.ContainsKey("id") == true;
        var id = hasId ? message!["id"]?.DeepClone() : null;
        if (method == "initialize")
        {
            _initializeLine = line;
        }
        else if (method == "notifications/initialized")
        {
            _initialized = true;
        }

        var link = Volatile.Read(ref _link);
        if (link is null && method == "tools/call")
        {
            link = await ReconnectAsync(cancellationToken).ConfigureAwait(false);
        }
        if (link is not null)
        {
            if (method is not null && hasId)
            {
                lock (_sync)
                {
                    _inFlight[Key(id)] = (id, method);
                }
            }
            if (await link.TrySendAsync(line, cancellationToken).ConfigureAwait(false))
            {
                return;
            }
            await GoOfflineAsync(link, "connection to the broker lost").ConfigureAwait(false);
            return; // The request was in flight and got its error response.
        }

        var response = HandleOffline(message, method, hasId, id);
        if (response is not null)
        {
            await WriteClientAsync(response.ToJsonString()).ConfigureAwait(false);
        }
    }

    private JsonObject? HandleOffline(JsonObject? message, string? method, bool hasId, JsonNode? id)
    {
        if (message is null)
        {
            return Error(null, -32700, "Parse error");
        }
        if (method is null || !hasId)
        {
            return null; // Notification or a response from the client: nothing to do.
        }
        return method switch
        {
            "initialize" => Result(id, McpSession.InitializeResult(message["params"] as JsonObject)),
            "ping" => Result(id, new JsonObject()),
            "tools/list" => Result(id, new JsonObject { ["tools"] = _offlineCatalog.Definitions.DeepClone() }),
            "tools/call" => Result(id, HintResult()),
            _ => Error(id, -32601, $"Method not found: {method}"),
        };
    }

    internal string Hint =>
        $"The wsb-mcp broker is not reachable ({_lastFailure}). It is not running, or another session " +
        "is connected (one at a time). Ask the user to run 'wsb-mcp start' (or 'wsb-mcp setup' if it was " +
        "never set up); 'wsb-mcp diag' shows details. Then call the tool again.";

    private JsonObject HintResult() => new()
    {
        ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = Hint }),
        ["isError"] = true,
    };

    /// <summary>Connects and replays the client's handshake, so the broker session matches.</summary>
    private async Task<BrokerLink?> ReconnectAsync(CancellationToken cancellationToken)
    {
        var link = await TryConnectAsync(cancellationToken).ConfigureAwait(false);
        if (link is null)
        {
            return null;
        }
        try
        {
            if (_initializeLine is not null && Parse(_initializeLine) is { } initialize)
            {
                initialize["id"] = ReplayId;
                if (!await link.TrySendAsync(initialize.ToJsonString(), cancellationToken).ConfigureAwait(false))
                {
                    throw new IOException("the broker closed the connection");
                }
                while (true)
                {
                    var reply = await link.ReadLineAsync(cancellationToken).WaitAsync(TimeSpan.FromSeconds(10), cancellationToken)
                        .ConfigureAwait(false) ?? throw new IOException(
                            "the broker closed the connection; it may be set up for a different agent account");
                    if (Parse(reply)?["id"] is JsonValue v && v.GetValueKind() == JsonValueKind.String &&
                        v.GetValue<string>() == ReplayId)
                    {
                        break;
                    }
                }
                if (_initialized &&
                    !await link.TrySendAsync("""{"jsonrpc":"2.0","method":"notifications/initialized"}""", cancellationToken)
                        .ConfigureAwait(false))
                {
                    throw new IOException("the broker closed the connection");
                }
            }
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or InvalidDataException)
        {
            _lastFailure = ex.Message;
            link.Dispose();
            return null;
        }
        GoOnline(link);
        return link;
    }

    private async Task<BrokerLink?> TryConnectAsync(CancellationToken cancellationToken)
    {
        // Identification lets the broker identify this account and run access checks for it,
        // but not act as it (a non-elevated broker would be capped at Identification anyway).
        var pipe = new NamedPipeClientStream(
            ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        try
        {
            await pipe.ConnectAsync(connectTimeout, cancellationToken).ConfigureAwait(false);
            return new BrokerLink(pipe);
        }
        catch (TimeoutException)
        {
            _lastFailure = $"no broker on pipe '{pipeName}'";
        }
        catch (UnauthorizedAccessException)
        {
            _lastFailure = $"the broker on pipe '{pipeName}' does not accept this account";
        }
        catch (IOException ex)
        {
            _lastFailure = ex.Message;
        }
        await pipe.DisposeAsync().ConfigureAwait(false);
        return null;
    }

    private void GoOnline(BrokerLink link)
    {
        Volatile.Write(ref _link, link);
        _ = PumpAsync(link);
    }

    private async Task PumpAsync(BrokerLink link)
    {
        try
        {
            while (await link.ReadLineAsync(CancellationToken.None).ConfigureAwait(false) is { } line)
            {
                if (Parse(line) is { } message && message.ContainsKey("id") && !message.ContainsKey("method"))
                {
                    lock (_sync)
                    {
                        _inFlight.Remove(Key(message["id"]));
                    }
                }
                await WriteClientAsync(line).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or ObjectDisposedException)
        {
        }
        await GoOfflineAsync(link, "the broker closed the connection; if this repeats, it may be set up for a different agent account").ConfigureAwait(false);
    }

    /// <summary>Answers every request still waiting on the lost broker, then stays offline.</summary>
    private async Task GoOfflineAsync(BrokerLink link, string reason)
    {
        List<(JsonNode? Id, string Method)> pending;
        lock (_sync)
        {
            if (!ReferenceEquals(_link, link))
            {
                return;
            }
            _link = null;
            pending = [.. _inFlight.Values];
            _inFlight.Clear();
        }
        _lastFailure = reason;
        link.Dispose();
        foreach (var (id, method) in pending)
        {
            var response = method == "tools/call" ? Result(id, HintResult()) : Error(id, -32000, Hint);
            await WriteClientAsync(response.ToJsonString()).ConfigureAwait(false);
        }
    }

    private async Task DrainAsync(TimeSpan limit)
    {
        var deadline = DateTime.UtcNow + limit;
        while (DateTime.UtcNow < deadline)
        {
            lock (_sync)
            {
                if (_inFlight.Count == 0 || _link is null)
                {
                    return;
                }
            }
            await Task.Delay(50).ConfigureAwait(false);
        }
    }

    private async Task WriteClientAsync(string line)
    {
        await _clientWrite.WaitAsync().ConfigureAwait(false);
        try
        {
            await clientOutput.WriteAsync(Encoding.UTF8.GetBytes(line + "\n")).ConfigureAwait(false);
            await clientOutput.FlushAsync().ConfigureAwait(false);
        }
        catch (IOException)
        {
            // The MCP host went away; the read loop ends with it.
        }
        finally
        {
            _clientWrite.Release();
        }
    }

    private static JsonObject? Parse(string line)
    {
        try
        {
            return JsonNode.Parse(line, documentOptions: ParseOptions) as JsonObject;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string Key(JsonNode? id) => id?.ToJsonString() ?? "null";

    private static JsonObject Result(JsonNode? id, JsonNode result) =>
        new() { ["jsonrpc"] = "2.0", ["id"] = id?.DeepClone(), ["result"] = result };

    private static JsonObject Error(JsonNode? id, int code, string message) =>
        new() { ["jsonrpc"] = "2.0", ["id"] = id?.DeepClone(), ["error"] = new JsonObject { ["code"] = code, ["message"] = message } };

    private sealed class BrokerLink(NamedPipeClientStream pipe) : IDisposable
    {
        private readonly LineReader _reader = new(pipe, McpSession.MaxMessageBytes);

        public Task<string?> ReadLineAsync(CancellationToken cancellationToken) => _reader.ReadLineAsync(cancellationToken);

        public async Task<bool> TrySendAsync(string line, CancellationToken cancellationToken)
        {
            try
            {
                await pipe.WriteAsync(Encoding.UTF8.GetBytes(line + "\n"), cancellationToken).ConfigureAwait(false);
                await pipe.FlushAsync(cancellationToken).ConfigureAwait(false);
                return true;
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
            {
                return false;
            }
        }

        public void Dispose() => pipe.Dispose();
    }
}
