using System.Security.AccessControl;

namespace WsbMcp.Tests;

public sealed class PathValidatorTests : IDisposable
{
    private readonly WorkDir _work = new();
    private readonly string _root;
    private readonly PathValidator _validator;
    private readonly SelfClient _client = new();

    public PathValidatorTests()
    {
        _root = _work.Dir("root");
        _validator = new PathValidator(_root);
    }

    public void Dispose() => _work.Dispose();

    private ToolException Reject(string path, DirectoryAccess access = DirectoryAccess.Read) =>
        Assert.Throws<ToolException>(() => _validator.Acquire(path, access, _client, "p").Dispose());

    [Test]
    public void AcceptsDirectoryBelowRootAndTheRootItself()
    {
        var dir = _work.Dir(@"root\a\b");
        using (var lease = _validator.Acquire(dir, DirectoryAccess.ReadWrite, _client, "p"))
        {
            Assert.Equal(dir, lease.FinalPath, "final path");
        }
        using var rootLease = _validator.Acquire(_root, DirectoryAccess.Read, _client, "p");
        Assert.Equal(_validator.Root, rootLease.FinalPath, "root");
    }

    [Test]
    public void ResolvesDotDotAndCaseToFinalPath()
    {
        var dir = _work.Dir(@"root\a");
        using var lease = _validator.Acquire(Path.Combine(_root, "x", "..", "A").ToUpperInvariant(),
            DirectoryAccess.Read, _client, "p");
        // GetFinalPathNameByHandle returns the on-disk casing.
        Assert.Equal(dir, lease.FinalPath, "final path");
    }

    [Test]
    public void RejectsNonLocalOrMalformedPaths()
    {
        foreach (var path in new[]
                 {
                     "", " ", "relative\\dir", "C:relative", @"\\server\share\x", @"\\?\C:\x", @"\\.\C:\x",
                     _root + ":stream", _root + "\0", @"\Windows",
                 })
        {
            Assert.Contains("rule 1", Reject(path).Message);
        }
    }

    [Test]
    public void RejectsMissingDirectoryAndFile()
    {
        Assert.Contains("does not exist", Reject(Path.Combine(_root, "missing")).Message);
        var file = Path.Combine(_root, "file.txt");
        File.WriteAllText(file, "x");
        Assert.Contains("not a directory", Reject(file).Message);
    }

    [Test]
    public void RejectsOutsideRootIncludingPrefixSibling()
    {
        Assert.Contains("rule 3", Reject(_work.Dir("outside")).Message);
        Assert.Contains("rule 3", Reject(_work.Dir("root2")).Message);
        Assert.Contains("rule 3", Reject(_root + @"\..").Message);
    }

    [Test]
    public void RejectsJunctionEscapingRoot()
    {
        var outside = _work.Dir("secret");
        var link = Path.Combine(_root, "link");
        WorkDir.CreateJunction(link, outside);
        var error = Reject(link);
        Assert.Contains("rule 3", error.Message);
        Assert.Contains(outside, error.Message);
        // Also via a path that traverses the junction.
        _work.Dir(@"secret\sub");
        Assert.Contains("rule 3", Reject(Path.Combine(link, "sub")).Message);
    }

    [Test]
    public void AcceptsJunctionStayingInsideRoot()
    {
        var target = _work.Dir(@"root\target");
        var link = Path.Combine(_root, "link");
        WorkDir.CreateJunction(link, target);
        using var lease = _validator.Acquire(link, DirectoryAccess.Read, _client, "p");
        Assert.Equal(target, lease.FinalPath, "final path");
    }

    [Test]
    public void RejectsWithoutClientReadAccess()
    {
        var dir = _work.Dir(@"root\noread");
        _work.Deny(dir, FileSystemRights.ListDirectory);
        // Broker and client are the same account in-process, so the broker's own pin (rule 2)
        // fails first; across accounts this is rule 4. Either way the path is rejected.
        var message = Reject(dir).Message;
        Assert.True(message.Contains("rule 4", StringComparison.Ordinal) ||
                    message.Contains("Access is denied", StringComparison.Ordinal), message);
    }

    [Test]
    public void RejectsWithoutClientWriteAccessOnlyForOutput()
    {
        var dir = _work.Dir(@"root\nowrite");
        _work.Deny(dir, FileSystemRights.CreateFiles);
        using (_validator.Acquire(dir, DirectoryAccess.Read, _client, "p"))
        {
        }
        Assert.Contains("rule 4", Reject(dir, DirectoryAccess.ReadWrite).Message);
    }

    [Test]
    public void LeasePreventsSwappingDirectoryOrAncestor()
    {
        var dir = _work.Dir(@"root\parent\child");
        using (_validator.Acquire(dir, DirectoryAccess.Read, _client, "p"))
        {
            Assert.Throws<IOException>(() => Directory.Move(dir, dir + "-moved"));
            Assert.Throws<IOException>(() => Directory.Move(Path.Combine(_root, "parent"), Path.Combine(_root, "parent-moved")));
            Assert.Throws<IOException>(() => Directory.Delete(dir));
        }
        Directory.Move(dir, dir + "-moved"); // Released afterwards.
    }

    [Test]
    public void NormalizesFinalPaths()
    {
        Assert.Equal(@"C:\x", PathValidator.NormalizeFinalPath(@"\\?\C:\x\"));
        Assert.Equal(@"C:\", PathValidator.NormalizeFinalPath(@"\\?\C:\"));
        Assert.Equal(null, PathValidator.NormalizeFinalPath(@"\\?\UNC\server\share"));
        Assert.Equal(null, PathValidator.NormalizeFinalPath(@"\\?\Volume{0}\x"));
        Assert.True(PathValidator.IsUnder(@"C:\root\a", @"C:\root"));
        Assert.True(PathValidator.IsUnder(@"c:\ROOT", @"C:\root"));
        Assert.True(!PathValidator.IsUnder(@"C:\root2", @"C:\root"));
        Assert.True(PathValidator.IsUnder(@"C:\any", @"C:\"));
    }
}
