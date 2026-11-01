using System.IO.Pipes;
using System.Runtime.ExceptionServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json.Nodes;

namespace WsbMcp;

/// <summary>Serves one verified client at a time on an ACL-protected named pipe.</summary>
public sealed class PipeHost(
    string pipeName, SecurityIdentifier agentSid, SandboxManager sandbox, ToolCatalog catalog, IBrokerLog log)
{
    public static PipeSecurity CreateSecurity(SecurityIdentifier agentSid)
    {
        var self = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Cannot determine the broker account SID.");
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(self, PipeAccessRights.FullControl, AccessControlType.Allow));
        if (!agentSid.Equals(self))
        {
            // ReadWrite excludes CreateNewInstance, so the agent cannot add server instances.
            security.AddAccessRule(new PipeAccessRule(agentSid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        }
        return security;
    }

    /// <summary>Raised once the pipe exists and accepts connections.</summary>
    public event Action? Listening;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        // FirstPipeInstance fails if anyone else already owns the name; a single instance that
        // is reused (Disconnect + WaitForConnection) leaves no window for squatting.
        using var server = NamedPipeServerStreamAcl.Create(
            pipeName, PipeDirection.InOut, maxNumberOfServerInstances: 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 0, 0, CreateSecurity(agentSid));
        log.Write("broker.listening", new JsonObject { ["pipe"] = $@"\\.\pipe\{pipeName}" });
        Listening?.Invoke();

        while (true)
        {
            await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            var client = new PipeClientIdentity(server);
            var verified = false;
            try
            {
                if (!client.Verify(agentSid, out var reason))
                {
                    log.Write("client.rejected", new JsonObject { ["client"] = client.Name, ["reason"] = reason });
                    continue;
                }
                verified = true;
                log.Write("client.connected", new JsonObject { ["client"] = client.Name });
                await new McpSession(server, server, sandbox, client, log, catalog)
                    .RunAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (IOException ex)
            {
                log.Write("client.io_error", new JsonObject { ["client"] = client.Name, ["error"] = ex.Message });
            }
            finally
            {
                if (verified)
                {
                    await StopQuietlyAsync(sandbox, "client disconnected", log).ConfigureAwait(false);
                    log.Write("client.disconnected", new JsonObject { ["client"] = client.Name });
                }
                try
                {
                    server.Disconnect();
                }
                catch (InvalidOperationException)
                {
                    // Not connected anymore.
                }
            }
        }
    }

    internal static async Task StopQuietlyAsync(SandboxManager sandbox, string reason, IBrokerLog log)
    {
        try
        {
            await sandbox.StopAsync(reason, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is ToolException or IOException or InvalidOperationException)
        {
            log.Write("guest.stop_failed", new JsonObject { ["reason"] = reason, ["error"] = ex.Message });
        }
    }
}

internal sealed class PipeClientIdentity(NamedPipeServerStream pipe) : IClientIdentity
{
    public string Name { get; private set; } = "(unknown)";

    public void RunAsClient(Action action)
    {
        ExceptionDispatchInfo? failure = null;
        pipe.RunAsClient(() =>
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                failure = ExceptionDispatchInfo.Capture(ex);
            }
        });
        failure?.Throw();
    }

    /// <summary>Accepts only the configured agent account connecting with impersonation level.</summary>
    public bool Verify(SecurityIdentifier expected, out string reason)
    {
        SecurityIdentifier? sid = null;
        var level = TokenImpersonationLevel.None;
        try
        {
            RunAsClient(() =>
            {
                using var identity = WindowsIdentity.GetCurrent(ifImpersonating: true);
                if (identity is not null)
                {
                    sid = identity.User;
                    level = identity.ImpersonationLevel;
                    Name = identity.Name;
                }
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            reason = $"cannot identify client: {ex.Message}";
            return false;
        }

        if (sid is null || !sid.Equals(expected))
        {
            reason = $"client SID {sid?.Value ?? "(none)"} is not the configured agent {expected.Value}";
            return false;
        }
        if (level is not (TokenImpersonationLevel.Impersonation or TokenImpersonationLevel.Delegation))
        {
            reason = $"client allowed impersonation level {level}; 'Impersonation' is required for access checks";
            return false;
        }
        reason = string.Empty;
        return true;
    }
}
