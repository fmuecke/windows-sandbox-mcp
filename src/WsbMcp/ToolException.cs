namespace WsbMcp;

/// <summary>An expected, client-visible tool failure (reported as an MCP tool error).</summary>
public sealed class ToolException(string message) : Exception(message);
