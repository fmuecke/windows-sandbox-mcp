using System.Text.Json;
using System.Text.Json.Nodes;

namespace WsbMcp;

public interface IBrokerLog
{
    void Write(string eventName, JsonObject? data = null);
}

/// <summary>Append-only JSON-lines log in a host-only location.</summary>
public sealed class BrokerLog(string path, bool echoToConsole) : IBrokerLog
{
    private readonly Lock _lock = new();

    public void Write(string eventName, JsonObject? data = null)
    {
        var entry = new JsonObject
        {
            ["time"] = DateTimeOffset.Now.ToString("o"),
            ["event"] = eventName,
        };
        if (data is not null)
        {
            entry["data"] = data;
        }
        var line = entry.ToJsonString(new JsonSerializerOptions { WriteIndented = false });
        lock (_lock)
        {
            File.AppendAllText(path, line + Environment.NewLine);
            if (echoToConsole)
            {
                Console.Error.WriteLine(line);
            }
        }
    }
}

public sealed class NullBrokerLog : IBrokerLog
{
    public static readonly NullBrokerLog Instance = new();

    public void Write(string eventName, JsonObject? data = null)
    {
    }
}
