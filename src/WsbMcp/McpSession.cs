using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WsbMcp;

/// <summary>
/// Minimal MCP server (JSON-RPC 2.0, newline-delimited JSON) exposing the sandbox tools.
/// Requests are handled sequentially; the client is untrusted.
/// </summary>
public sealed class McpSession(
    Stream input, Stream output, SandboxManager sandbox, IClientIdentity client, IBrokerLog log, ToolCatalog catalog)
{
    public const int MaxMessageBytes = 1024 * 1024;

    internal static readonly string[] SupportedProtocolVersions = ["2025-06-18", "2025-03-26", "2024-11-05"];

    private static readonly JsonDocumentOptions ParseOptions = new() { MaxDepth = 32 };

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var reader = new LineReader(input, MaxMessageBytes);
        while (true)
        {
            string? line;
            try
            {
                line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidDataException ex)
            {
                log.Write("session.protocol_violation", new JsonObject { ["error"] = ex.Message });
                return; // Cannot resynchronize after an oversized message; drop the client.
            }
            if (line is null)
            {
                return;
            }
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }
            var response = await HandleAsync(line, cancellationToken).ConfigureAwait(false);
            if (response is not null)
            {
                var bytes = Encoding.UTF8.GetBytes(response.ToJsonString() + "\n");
                await output.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
        }
    }

    internal async Task<JsonObject?> HandleAsync(string line, CancellationToken cancellationToken)
    {
        JsonNode? message;
        try
        {
            message = JsonNode.Parse(line, documentOptions: ParseOptions);
        }
        catch (JsonException)
        {
            return Error(null, -32700, "Parse error");
        }
        if (message is not JsonObject request ||
            request["jsonrpc"] is not JsonValue version || version.GetValueKind() != JsonValueKind.String ||
            version.GetValue<string>() != "2.0")
        {
            return Error(null, -32600, "Invalid request");
        }

        var hasId = request.TryGetPropertyValue("id", out var idNode);
        var id = idNode?.DeepClone();
        if (hasId && id is not null && id.GetValueKind() is not (JsonValueKind.String or JsonValueKind.Number))
        {
            return Error(null, -32600, "Invalid request id");
        }
        if (request["method"] is not JsonValue methodValue || methodValue.GetValueKind() != JsonValueKind.String)
        {
            // A response from the client (we never send requests) or garbage without an id.
            return hasId && request["result"] is null && request["error"] is null ? Error(id, -32600, "Invalid request") : null;
        }
        var method = methodValue.GetValue<string>();
        if (!hasId)
        {
            return null; // Notification (initialized, cancelled, ...): nothing to do.
        }

        var parameters = request["params"] as JsonObject;
        try
        {
            return method switch
            {
                "initialize" => Result(id, Initialize(parameters)),
                "ping" => Result(id, new JsonObject()),
                "tools/list" => Result(id, new JsonObject { ["tools"] = catalog.Definitions.DeepClone() }),
                "tools/call" => await CallToolAsync(id, parameters, cancellationToken).ConfigureAwait(false),
                _ => Error(id, -32601, $"Method not found: {method}"),
            };
        }
        catch (InvalidParamsException ex)
        {
            return Error(id, -32602, ex.Message);
        }
    }

    private static JsonObject Initialize(JsonObject? parameters)
    {
        var requested = parameters?["protocolVersion"] is JsonValue v && v.GetValueKind() == JsonValueKind.String
            ? v.GetValue<string>()
            : null;
        var version = requested is not null && SupportedProtocolVersions.Contains(requested)
            ? requested
            : SupportedProtocolVersions[0];
        return new JsonObject
        {
            ["protocolVersion"] = version,
            ["capabilities"] = new JsonObject { ["tools"] = new JsonObject { ["listChanged"] = false } },
            ["serverInfo"] = new JsonObject { ["name"] = "wsb-mcp", ["version"] = ToolCatalog.Version },
            ["instructions"] = ToolCatalog.Instructions,
        };
    }

    private async Task<JsonObject> CallToolAsync(JsonNode? id, JsonObject? parameters, CancellationToken cancellationToken)
    {
        if (parameters?["name"] is not JsonValue nameValue || nameValue.GetValueKind() != JsonValueKind.String)
        {
            throw new InvalidParamsException("tools/call requires a string 'name'.");
        }
        var name = nameValue.GetValue<string>();
        if (!catalog.Names.Contains(name))
        {
            throw new InvalidParamsException($"Unknown tool: {name}");
        }
        var arguments = parameters["arguments"] switch
        {
            null => new JsonObject(),
            JsonObject obj => obj,
            _ => throw new InvalidParamsException("'arguments' must be an object."),
        };

        var started = DateTimeOffset.UtcNow;
        JsonObject structured;
        string? error = null;
        try
        {
            structured = await InvokeToolAsync(name, new ToolArguments(arguments), cancellationToken).ConfigureAwait(false);
        }
        catch (ToolException ex)
        {
            error = ex.Message;
            structured = new JsonObject { ["error"] = ex.Message };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            error = $"Internal broker error ({ex.GetType().Name}): {ex.Message}";
            structured = new JsonObject { ["error"] = error };
        }

        log.Write("tool.call", new JsonObject
        {
            ["client"] = client.Name,
            ["tool"] = name,
            ["arguments"] = arguments.DeepClone(),
            ["result"] = structured.DeepClone(),
            ["isError"] = error is not null,
            ["seconds"] = Math.Round((DateTimeOffset.UtcNow - started).TotalSeconds, 2),
        });

        var result = new JsonObject
        {
            ["content"] = new JsonArray(new JsonObject
            {
                ["type"] = "text",
                ["text"] = error ?? structured.ToJsonString(),
            }),
            ["isError"] = error is not null,
        };
        if (error is null)
        {
            result["structuredContent"] = structured;
        }
        return Result(id, result);
    }

    private Task<JsonObject> InvokeToolAsync(string name, ToolArguments arguments, CancellationToken cancellationToken)
    {
        switch (name)
        {
            case ToolCatalog.Start:
                arguments.AllowOnly("inputPath", "outputPath");
                return sandbox.StartAsync(arguments.String("inputPath"), arguments.String("outputPath"), client, cancellationToken);
            case ToolCatalog.Exec:
                arguments.AllowOnly("command", "workingDirectory", "runAs", "timeoutSeconds");
                var runAs = arguments.String("runAs") switch
                {
                    null or "system" => RunAs.System,
                    "user" => RunAs.User,
                    _ => throw new ToolException("runAs must be 'system' or 'user'."),
                };
                return sandbox.ExecAsync(
                    arguments.String("command") ?? throw new ToolException("command is required."),
                    arguments.String("workingDirectory"),
                    runAs,
                    arguments.Int("timeoutSeconds"),
                    cancellationToken);
            case ToolCatalog.Status:
                arguments.AllowOnly();
                return sandbox.StatusAsync(cancellationToken);
            case ToolCatalog.Stop:
                arguments.AllowOnly();
                return sandbox.StopAsync("sandbox_stop", cancellationToken);
            default:
                throw new InvalidParamsException($"Unknown tool: {name}");
        }
    }

    private static JsonObject Result(JsonNode? id, JsonNode result) =>
        new() { ["jsonrpc"] = "2.0", ["id"] = id, ["result"] = result };

    private static JsonObject Error(JsonNode? id, int code, string message) =>
        new() { ["jsonrpc"] = "2.0", ["id"] = id, ["error"] = new JsonObject { ["code"] = code, ["message"] = message } };

    private sealed class InvalidParamsException(string message) : Exception(message);

    private sealed class ToolArguments(JsonObject arguments)
    {
        public void AllowOnly(params string[] names)
        {
            foreach (var (key, _) in arguments)
            {
                if (!names.Contains(key, StringComparer.Ordinal))
                {
                    throw new ToolException($"Unknown argument '{key}'.");
                }
            }
        }

        public string? String(string name) => arguments[name] switch
        {
            null => null,
            JsonValue v when v.GetValueKind() == JsonValueKind.String => v.GetValue<string>(),
            _ => throw new ToolException($"{name} must be a string."),
        };

        public int? Int(string name) => arguments[name] switch
        {
            null => null,
            JsonValue v when v.TryGetValue<int>(out var i) => i,
            JsonValue v when v.TryGetValue<double>(out var d) && d == Math.Floor(d) && d is >= int.MinValue and <= int.MaxValue => (int)d,
            _ => throw new ToolException($"{name} must be an integer."),
        };
    }
}

/// <summary>Reads newline-delimited UTF-8 messages with a hard size limit.</summary>
internal sealed class LineReader(Stream stream, int maxLineBytes)
{
    private readonly byte[] _buffer = new byte[64 * 1024];
    private readonly MemoryStream _line = new();
    private int _start;
    private int _end;

    public async Task<string?> ReadLineAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            if (_start == _end)
            {
                _start = 0;
                _end = await stream.ReadAsync(_buffer, cancellationToken).ConfigureAwait(false);
                if (_end == 0)
                {
                    return _line.Length > 0 ? Take() : null;
                }
            }
            var newline = Array.IndexOf(_buffer, (byte)'\n', _start, _end - _start);
            var count = (newline < 0 ? _end : newline) - _start;
            if (_line.Length + count > maxLineBytes)
            {
                throw new InvalidDataException($"Message exceeds {maxLineBytes} bytes.");
            }
            _line.Write(_buffer, _start, count);
            if (newline < 0)
            {
                _start = _end;
                continue;
            }
            _start = newline + 1;
            return Take();
        }
    }

    private string Take()
    {
        var text = Encoding.UTF8.GetString(_line.GetBuffer(), 0, (int)_line.Length).TrimEnd('\r');
        _line.SetLength(0);
        return text;
    }
}
