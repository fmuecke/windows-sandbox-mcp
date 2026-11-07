// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// https://github.com/fmuecke/windows-sandbox-mcp
using System.Security.AccessControl;
using System.Security.Principal;

namespace WsbMcp;

/// <summary>
/// Named event that asks a running broker to shut down gracefully (stop the guest, then exit).
/// Only the broker user and SYSTEM may open it. If it already exists when the broker starts,
/// someone else created it, so the broker refuses to start (SPEC.md "Logon task").
/// </summary>
public static class StopSignal
{
    public static string Name(string pipeName) => $@"Local\wsb-mcp-{pipeName}-stop";

    public static EventWaitHandle Create(string pipeName)
    {
        var self = WindowsIdentity.GetCurrent().User!;
        var security = new EventWaitHandleSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new EventWaitHandleAccessRule(self, EventWaitHandleRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new EventWaitHandleAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), EventWaitHandleRights.FullControl, AccessControlType.Allow));

        var handle = EventWaitHandleAcl.Create(false, EventResetMode.ManualReset, Name(pipeName), out var createdNew, security);
        if (!createdNew)
        {
            handle.Dispose();
            throw new InvalidOperationException(
                $"The stop event '{Name(pipeName)}' already exists: another broker is running, or another process " +
                "created it to interfere. Refusing to start.");
        }
        return handle;
    }

    /// <summary>True while a broker process still holds the event (it disappears when the process exits).</summary>
    public static bool Exists(string pipeName)
    {
        try
        {
            if (!EventWaitHandle.TryOpenExisting(Name(pipeName), out var handle))
            {
                return false;
            }
            handle.Dispose();
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return true; // Exists, but belongs to someone else.
        }
    }

    /// <summary>Signals a running broker; false if none is listening.</summary>
    public static bool TrySignal(string pipeName)
    {
        if (!EventWaitHandle.TryOpenExisting(Name(pipeName), out var handle))
        {
            return false;
        }
        using (handle)
        {
            handle.Set();
        }
        return true;
    }
}
