using System.Text;
using System.Text.Json.Nodes;

namespace WsbMcp.Tests;

public sealed class McpSessionTests : IDisposable
{
    private readonly WorkDir _work = new();
    private readonly ScriptedWsb _wsb = new();
    private readonly McpSession _session;

    public McpSessionTests()
    {
        var root = _work.Dir("root");
        _session = new McpSession(Stream.Null, Stream.Null, Fixtures.Manager(_wsb, root), new SelfClient(),
            NullBrokerLog.Instance, new ToolCatalog(root, 600, TimeSpan.FromMinutes(30)));
    }

    public void Dispose() => _work.Dispose();

    private async Task<JsonObject?> Send(string json) => await _session.HandleAsync(json, CancellationToken.None);

    private async Task<JsonObject> Call(string tool, string arguments = "{}")
    {
        var response = await Send($$$"""{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"{{{tool}}}","arguments":{{{arguments}}}}}""");
        return (JsonObject)response!["result"]!;
    }

    [Test]
    public async Task InitializeNegotiatesProtocolVersion()
    {
        var response = await Send("""{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}""");
        Assert.Equal("2025-03-26", (string?)response!["result"]!["protocolVersion"]);
        Assert.Equal("wsb-mcp", (string?)response["result"]!["serverInfo"]!["name"]);
        Assert.True(response["result"]!["capabilities"]!["tools"] is JsonObject, "tools capability");

        response = await Send("""{"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"1999-01-01"}}""");
        Assert.Equal(McpSession.SupportedProtocolVersions[0], (string?)response!["result"]!["protocolVersion"]);
        Assert.Equal("a", (string?)response["id"]);
    }

    [Test]
    public async Task ToolsListAdvertisesFourToolsWithClosedSchemas()
    {
        var response = await Send("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""");
        var tools = (JsonArray)response!["result"]!["tools"]!;
        Assert.Equal("sandbox_start,sandbox_exec,sandbox_status,sandbox_stop",
            string.Join(',', tools.Select(t => (string?)t!["name"])));
        foreach (var tool in tools)
        {
            Assert.Equal(false, (bool?)tool!["inputSchema"]!["additionalProperties"]);
        }
        Assert.Contains("NOT returned", (string?)tools[1]!["description"]);
    }

    [Test]
    public async Task ToolCallReturnsStructuredContent()
    {
        var result = await Call("sandbox_status");
        Assert.Equal(false, (bool?)result["isError"]);
        Assert.Equal(false, (bool?)result["structuredContent"]!["running"]);
        Assert.Contains("\"running\":false", (string?)result["content"]![0]!["text"]);
    }

    [Test]
    public async Task ToolFailuresAreToolErrors()
    {
        var result = await Call("sandbox_exec", """{"command":"x"}""");
        Assert.Equal(true, (bool?)result["isError"]);
        Assert.Contains("sandbox_start", (string?)result["content"]![0]!["text"]);

        result = await Call("sandbox_status", """{"verbose":true}""");
        Assert.Contains("Unknown argument 'verbose'", (string?)result["content"]![0]!["text"]);

        result = await Call("sandbox_exec", """{"command":"x","runAs":"admin"}""");
        Assert.Contains("runAs", (string?)result["content"]![0]!["text"]);

        result = await Call("sandbox_exec", """{"command":"x","timeoutSeconds":"10"}""");
        Assert.Contains("integer", (string?)result["content"]![0]!["text"]);
    }

    [Test]
    public async Task FullFlowOverTools()
    {
        Assert.Equal(false, (bool?)(await Call("sandbox_start"))["isError"]);
        var exec = await Call("sandbox_exec", """{"command":"cmd.exe /c exit 0","timeoutSeconds":30}""");
        Assert.Equal(0, (int?)exec["structuredContent"]!["exitCode"]);
        Assert.Equal(true, (bool?)(await Call("sandbox_stop"))["structuredContent"]!["stopped"]);
    }

    [Test]
    public async Task ProtocolErrors()
    {
        Assert.Equal(-32700, (int?)(await Send("{not json"))!["error"]!["code"]);
        Assert.Equal(-32600, (int?)(await Send("""{"jsonrpc":"1.0","id":1,"method":"ping"}"""))!["error"]!["code"]);
        Assert.Equal(-32600, (int?)(await Send("""[{"jsonrpc":"2.0","id":1,"method":"ping"}]"""))!["error"]!["code"]);
        Assert.Equal(-32601, (int?)(await Send("""{"jsonrpc":"2.0","id":1,"method":"resources/list"}"""))!["error"]!["code"]);
        Assert.Equal(-32602, (int?)(await Send("""{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rm_rf"}}"""))!["error"]!["code"]);
        Assert.Equal(null, await Send("""{"jsonrpc":"2.0","method":"notifications/initialized"}"""));
        Assert.Equal(null, await Send("""{"jsonrpc":"2.0","id":5,"result":{}}"""));
        Assert.True((await Send("""{"jsonrpc":"2.0","id":1,"method":"ping"}"""))!["result"] is JsonObject, "ping");
    }

    [Test]
    public async Task SessionStreamsResponsesAndDropsOversizedMessages()
    {
        var root = _work.Dir("root2");
        var requests = """{"jsonrpc":"2.0","id":1,"method":"ping"}""" + "\r\n\n" +
                       """{"jsonrpc":"2.0","method":"notifications/initialized"}""" + "\n" +
                       """{"jsonrpc":"2.0","id":2,"method":"ping"}""" + "\n" +
                       new string('x', McpSession.MaxMessageBytes + 1) + "\n" +
                       """{"jsonrpc":"2.0","id":3,"method":"ping"}""" + "\n";
        var output = new MemoryStream();
        var session = new McpSession(new MemoryStream(Encoding.UTF8.GetBytes(requests)), output,
            Fixtures.Manager(_wsb, root), new SelfClient(), NullBrokerLog.Instance, new ToolCatalog(root, 600, TimeSpan.FromMinutes(30)));
        await session.RunAsync(CancellationToken.None);

        var lines = Encoding.UTF8.GetString(output.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length, "responses before the oversized message only");
        Assert.Equal(2, (int?)JsonNode.Parse(lines[1])!["id"]);
    }
}
