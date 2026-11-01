// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// https://github.com/fmuecke/windows-sandbox-mcp
namespace WsbMcp;

/// <summary>An expected, client-visible tool failure (reported as an MCP tool error).</summary>
public sealed class ToolException(string message) : Exception(message);
