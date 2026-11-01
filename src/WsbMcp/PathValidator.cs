using System.ComponentModel;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace WsbMcp;

public enum DirectoryAccess
{
    Read,
    ReadWrite,
}

/// <summary>The connected (untrusted) client, used to run access checks for its account.</summary>
public interface IClientIdentity
{
    string Name { get; }

    /// <summary>Impersonation token of the client (Identification level suffices), with TOKEN_QUERY.</summary>
    SafeAccessTokenHandle Token { get; }
}

/// <summary>
/// An open handle on a validated directory. While held, the directory and its ancestors
/// cannot be renamed or deleted, so the validated path cannot be swapped (TOCTOU).
/// </summary>
public sealed class DirectoryLease(string finalPath, SafeFileHandle handle) : IDisposable
{
    public string FinalPath { get; } = finalPath;

    public void Dispose() => handle.Dispose();
}

/// <summary>Implements the folder mapping rules from SPEC.md.</summary>
public sealed partial class PathValidator
{
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private const int ErrorAccessDenied = 5;
    private const int ErrorSharingViolation = 32;

    public PathValidator(string allowedRoot)
    {
        Root = ResolveFinalDirectory(allowedRoot);
    }

    /// <summary>Final (canonical, reparse-free) path of the allowed root.</summary>
    public string Root { get; }

    /// <summary>Resolves a host-trusted directory path (configuration) to its final path.</summary>
    public static string ResolveFinalDirectory(string path)
    {
        using var handle = Native.TryOpen(path, Native.FILE_READ_ATTRIBUTES,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE, out var error)
            ?? throw new InvalidOperationException($"Cannot open '{path}': {Native.DescribeError(error)}");
        if (!Native.IsDirectory(handle))
        {
            throw new InvalidOperationException($"'{path}' is not a directory.");
        }
        return NormalizeFinalPath(Native.GetFinalPath(handle))
            ?? throw new InvalidOperationException($"'{path}' does not resolve to a local drive path.");
    }

    public bool IsUnderRoot(string finalPath) => IsUnder(finalPath, Root);

    public static bool IsUnder(string finalPath, string finalRoot)
    {
        if (string.Equals(finalPath, finalRoot, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        var prefix = finalRoot.EndsWith('\\') ? finalRoot : finalRoot + "\\";
        return finalPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Validates a client-supplied host path and returns a lease that pins the directory.
    /// Throws <see cref="ToolException"/> naming the rule that failed.
    /// </summary>
    public DirectoryLease Acquire(string path, DirectoryAccess access, IClientIdentity client, string parameter)
    {
        // Rule 1: absolute local drive path, no device/UNC/stream syntax.
        if (string.IsNullOrWhiteSpace(path) || path.Contains('\0') || !DrivePath().IsMatch(path) ||
            path.IndexOf(':', 2) >= 0)
        {
            throw new ToolException($"{parameter}: must be an absolute local path like 'C:\\dir' (rule 1).");
        }

        // Rule 2: open without FILE_SHARE_DELETE and resolve the final path. The handle needs a
        // data access right (list): attribute-only handles do not take part in share-mode checks
        // and would not block rename/delete of the directory. READ_CONTROL is for the rule 4 check.
        var handle = Native.TryOpen(path,
            Native.FILE_LIST_DIRECTORY | Native.FILE_READ_ATTRIBUTES | Native.READ_CONTROL | Native.SYNCHRONIZE,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE, out var openError);
        if (handle is null)
        {
            var reason = openError switch
            {
                ErrorFileNotFound or ErrorPathNotFound => "does not exist",
                ErrorSharingViolation => "is locked for delete/rename by another process",
                _ => Native.DescribeError(openError),
            };
            throw new ToolException($"{parameter}: '{path}' {reason} (rule 2).");
        }

        try
        {
            string finalPath;
            try
            {
                if (!Native.IsDirectory(handle))
                {
                    throw new ToolException($"{parameter}: '{path}' is not a directory (rule 1).");
                }
                finalPath = NormalizeFinalPath(Native.GetFinalPath(handle))
                    ?? throw new ToolException($"{parameter}: '{path}' does not resolve to a local drive (rule 2).");
            }
            catch (Win32Exception ex)
            {
                throw new ToolException($"{parameter}: '{path}' cannot be inspected: {ex.Message} (rule 2).");
            }

            // Rule 3: below the configured root after resolving links.
            if (!IsUnderRoot(finalPath))
            {
                throw new ToolException(
                    $"{parameter}: '{path}' resolves to '{finalPath}', which is outside the allowed root '{Root}' (rule 3).");
            }

            // Rule 4: the client itself must have the required access. AccessCheck against the
            // pinned directory's security descriptor works with an Identification-level token.
            var desired = Native.FILE_LIST_DIRECTORY | Native.FILE_READ_ATTRIBUTES | Native.SYNCHRONIZE;
            if (access == DirectoryAccess.ReadWrite)
            {
                desired |= Native.FILE_ADD_FILE | Native.FILE_ADD_SUBDIRECTORY;
            }
            var accessError = Native.CheckAccess(handle, client.Token, desired);
            if (accessError != 0)
            {
                var what = access == DirectoryAccess.ReadWrite ? "read/write" : "read";
                var reason = accessError == ErrorAccessDenied ? "access denied" : Native.DescribeError(accessError);
                throw new ToolException(
                    $"{parameter}: '{client.Name}' lacks {what} access to '{finalPath}': {reason} (rule 4).");
            }

            // Rule 5: the caller keeps the lease until the share is established.
            return new DirectoryLease(finalPath, handle);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    /// <summary>Strips the \\?\ prefix; returns null for anything that is not a drive path.</summary>
    internal static string? NormalizeFinalPath(string finalPath)
    {
        if (finalPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        if (finalPath.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            finalPath = finalPath[4..];
        }
        if (!DrivePath().IsMatch(finalPath))
        {
            return null;
        }
        return finalPath.Length > 3 ? finalPath.TrimEnd('\\') : finalPath;
    }

    [GeneratedRegex(@"^[A-Za-z]:\\")]
    private static partial Regex DrivePath();
}
