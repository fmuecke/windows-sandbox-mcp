// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// https://github.com/fmuecke/windows-sandbox-mcp
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WsbMcp;

internal static class Native
{
    public const uint FILE_LIST_DIRECTORY = 0x0001;
    public const uint FILE_ADD_FILE = 0x0002;
    public const uint FILE_ADD_SUBDIRECTORY = 0x0004;
    public const uint FILE_READ_ATTRIBUTES = 0x0080;
    public const uint READ_CONTROL = 0x00020000;
    public const uint SYNCHRONIZE = 0x00100000;

    public const uint FILE_SHARE_READ = 0x1;
    public const uint FILE_SHARE_WRITE = 0x2;
    public const uint FILE_SHARE_DELETE = 0x4;

    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    public const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle hFile, [Out] char[] lpszFilePath, uint cchFilePath, uint dwFlags);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public uint CreationTimeLow, CreationTimeHigh;
        public uint LastAccessTimeLow, LastAccessTimeHigh;
        public uint LastWriteTimeLow, LastWriteTimeHigh;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh, FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh, FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle hFile, out ByHandleFileInformation info);

    /// <summary>Opens a directory (or file) handle; returns the Win32 error on failure.</summary>
    public static SafeFileHandle? TryOpen(string path, uint access, uint share, out int error)
    {
        var handle = CreateFileW(path, access, share, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            error = Marshal.GetLastWin32Error();
            handle.Dispose();
            return null;
        }
        error = 0;
        return handle;
    }

    private const uint FILE_NAME_NORMALIZED = 0x0;
    private const uint FILE_NAME_OPENED = 0x8;
    private const int ERROR_ACCESS_DENIED = 5;

    /// <summary>
    /// Returns the path of the opened object after all reparse points were resolved.
    /// Normalized names need list access on every ancestor; if that is denied, the opened
    /// name is used. It may keep 8.3 components, which can only cause false rejections.
    /// </summary>
    public static string GetFinalPath(SafeFileHandle handle)
    {
        try
        {
            return GetFinalPath(handle, FILE_NAME_NORMALIZED);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ERROR_ACCESS_DENIED)
        {
            return GetFinalPath(handle, FILE_NAME_OPENED);
        }
    }

    private static string GetFinalPath(SafeFileHandle handle, uint flags)
    {
        var buffer = new char[1024];
        while (true)
        {
            var length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, flags);
            if (length == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            if (length < buffer.Length)
            {
                return new string(buffer, 0, (int)length);
            }
            buffer = new char[length + 1];
        }
    }

    public static bool IsDirectory(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var info))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        return (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }

    private const int SE_FILE_OBJECT = 1;
    private const uint OWNER_SECURITY_INFORMATION = 0x1;
    private const uint GROUP_SECURITY_INFORMATION = 0x2;
    private const uint DACL_SECURITY_INFORMATION = 0x4;
    private const uint LABEL_SECURITY_INFORMATION = 0x10;

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(
        SafeFileHandle handle, int objectType, uint securityInfo,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr securityDescriptor);

    [StructLayout(LayoutKind.Sequential)]
    private struct GenericMapping
    {
        public uint Read, Write, Execute, All;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AccessCheck(
        IntPtr securityDescriptor, SafeAccessTokenHandle clientToken, uint desiredAccess, ref GenericMapping mapping,
        byte[] privilegeSet, ref uint privilegeSetLength, out uint grantedAccess, out bool accessStatus);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    /// <summary>
    /// Checks whether <paramref name="clientToken"/> (an impersonation token; Identification level
    /// suffices) is granted all of <paramref name="desiredAccess"/> by the security descriptor of the
    /// object behind <paramref name="handle"/> (opened with READ_CONTROL). Evaluates DACL, integrity
    /// label and restricting SIDs like a real open. Returns 0 or a Win32 error code.
    /// </summary>
    public static int CheckAccess(SafeFileHandle handle, SafeAccessTokenHandle clientToken, uint desiredAccess)
    {
        var error = GetSecurityInfo(handle, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var securityDescriptor);
        if (error != 0)
        {
            return (int)error;
        }
        try
        {
            var mapping = new GenericMapping { Read = 0x120089, Write = 0x120116, Execute = 0x1200A0, All = 0x1F01FF };
            var privileges = new byte[256];
            var length = (uint)privileges.Length;
            if (!AccessCheck(securityDescriptor, clientToken, desiredAccess, ref mapping, privileges, ref length,
                    out var granted, out var allowed))
            {
                return Marshal.GetLastWin32Error();
            }
            return allowed && (granted & desiredAccess) == desiredAccess ? 0 : ERROR_ACCESS_DENIED;
        }
        finally
        {
            LocalFree(securityDescriptor);
        }
    }

    public static string DescribeError(int error) => $"{new Win32Exception(error).Message} (0x{error:X8})";
}
