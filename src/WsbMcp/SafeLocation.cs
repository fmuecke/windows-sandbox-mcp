// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// https://github.com/fmuecke/windows-sandbox-mcp
using System.Security.AccessControl;
using System.Security.Principal;

namespace WsbMcp;

/// <summary>
/// Safe-location rule (SPEC.md): nobody but SYSTEM, Administrators, TrustedInstaller and the
/// broker user may replace the broker executable, plant files next to it, or rename/re-permission
/// any folder on its path.
/// </summary>
public static class SafeLocation
{
    private const FileSystemRights GenericAll = (FileSystemRights)0x10000000;
    private const FileSystemRights GenericWrite = (FileSystemRights)0x40000000;

    private const FileSystemRights Takeover =
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | FileSystemRights.Delete;

    /// <summary>Rights that let a SID modify or replace the file.</summary>
    internal const FileSystemRights FileWrite = Takeover |
        FileSystemRights.WriteData | FileSystemRights.AppendData |
        FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes;

    /// <summary>Rights on the executable's own folder: also no new files (DLL planting) or deletes.</summary>
    internal const FileSystemRights DirectoryWrite = Takeover |
        FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories | FileSystemRights.DeleteSubdirectoriesAndFiles;

    /// <summary>Rights on ancestors: creating new entries is harmless, renaming/re-permissioning is not.</summary>
    internal const FileSystemRights AncestorWrite = Takeover | FileSystemRights.DeleteSubdirectoriesAndFiles;

    /// <summary>NT SERVICE\TrustedInstaller (service SID, identical on every Windows installation).</summary>
    private static readonly SecurityIdentifier TrustedInstaller =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    /// <summary>Returns human-readable problems; empty means the location is safe.</summary>
    public static IReadOnlyList<string> FindProblems(string executablePath, SecurityIdentifier brokerUser)
    {
        var problems = new List<string>();
        string file;
        try
        {
            file = ResolveFinalFile(executablePath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return [$"Cannot resolve '{executablePath}': {ex.Message}"];
        }

        var trusted = TrustedSids(brokerUser);
        CheckObject(new FileInfo(file).GetAccessControl(), file, FileWrite, trusted, problems);

        var directory = new DirectoryInfo(Path.GetDirectoryName(file)!);
        CheckObject(directory.GetAccessControl(), directory.FullName, DirectoryWrite, trusted, problems);
        for (var ancestor = directory.Parent; ancestor is not null; ancestor = ancestor.Parent)
        {
            CheckObject(ancestor.GetAccessControl(), ancestor.FullName, AncestorWrite, trusted, problems);
        }
        return problems;
    }

    internal static HashSet<SecurityIdentifier> TrustedSids(SecurityIdentifier brokerUser) =>
    [
        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
        new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
        TrustedInstaller,
        brokerUser,
    ];

    /// <summary>Checks owner and effective (not inherit-only) allow ACEs of one object.</summary>
    internal static void CheckObject(
        FileSystemSecurity security, string path, FileSystemRights forbidden,
        IReadOnlySet<SecurityIdentifier> trusted, List<string> problems)
    {
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !trusted.Contains(owner))
        {
            problems.Add($"'{path}' is owned by {Describe(security.GetOwner(typeof(SecurityIdentifier)))}, " +
                         "who can change its permissions.");
        }
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow ||
                (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0 ||
                rule.IdentityReference is not SecurityIdentifier sid || trusted.Contains(sid))
            {
                continue;
            }
            var granted = Expand(rule.FileSystemRights) & forbidden;
            if (granted != 0)
            {
                problems.Add($"'{path}' grants {Describe(sid)} {granted}.");
            }
        }
    }

    /// <summary>Maps generic rights, which can appear in raw ACEs, to the specific file rights.</summary>
    internal static FileSystemRights Expand(FileSystemRights rights)
    {
        if ((rights & GenericAll) != 0)
        {
            rights |= FileSystemRights.FullControl;
        }
        if ((rights & GenericWrite) != 0)
        {
            rights |= FileSystemRights.Write;
        }
        return rights & ~(GenericAll | GenericWrite);
    }

    private static string ResolveFinalFile(string path)
    {
        using var handle = Native.TryOpen(path, Native.FILE_READ_ATTRIBUTES,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE, out var error)
            ?? throw new IOException(Native.DescribeError(error));
        return PathValidator.NormalizeFinalPath(Native.GetFinalPath(handle))
            ?? throw new InvalidOperationException("not on a local drive");
    }

    private static string Describe(IdentityReference? identity)
    {
        if (identity is null)
        {
            return "(nobody)";
        }
        try
        {
            return $"{identity.Translate(typeof(NTAccount)).Value} ({identity.Value})";
        }
        catch (IdentityNotMappedException)
        {
            return identity.Value;
        }
    }
}
