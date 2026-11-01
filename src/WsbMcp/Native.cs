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

    public static string DescribeError(int error) => $"{new Win32Exception(error).Message} (0x{error:X8})";
}
