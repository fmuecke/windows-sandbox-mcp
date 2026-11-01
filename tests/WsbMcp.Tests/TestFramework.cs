// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// https://github.com/fmuecke/windows-sandbox-mcp
using System.Diagnostics;
using System.Reflection;

namespace WsbMcp.Tests;

[AttributeUsage(AttributeTargets.Method)]
internal sealed class TestAttribute : Attribute;

internal static class Assert
{
    public static void True(bool condition, string message = "expected true")
    {
        if (!condition)
        {
            throw new AssertFailedException(message);
        }
    }

    public static void Equal<T>(T expected, T actual, string? what = null)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new AssertFailedException($"{what ?? "value"}: expected <{expected}>, got <{actual}>");
        }
    }

    public static void Contains(string expected, string? actual)
    {
        if (actual is null || !actual.Contains(expected, StringComparison.Ordinal))
        {
            throw new AssertFailedException($"expected text containing <{expected}>, got <{actual}>");
        }
    }

    public static T Throws<T>(Action action) where T : Exception
    {
        try
        {
            action();
        }
        catch (T ex)
        {
            return ex;
        }
        catch (Exception ex)
        {
            throw new AssertFailedException($"expected {typeof(T).Name}, got {ex.GetType().Name}: {ex.Message}");
        }
        throw new AssertFailedException($"expected {typeof(T).Name}, nothing thrown");
    }

    public static async Task<T> ThrowsAsync<T>(Func<Task> action) where T : Exception
    {
        try
        {
            await action();
        }
        catch (T ex)
        {
            return ex;
        }
        catch (Exception ex)
        {
            throw new AssertFailedException($"expected {typeof(T).Name}, got {ex.GetType().Name}: {ex.Message}");
        }
        throw new AssertFailedException($"expected {typeof(T).Name}, nothing thrown");
    }
}

internal sealed class AssertFailedException(string message) : Exception(message);

internal static class Runner
{
    public static async Task<int> Main(string[] args)
    {
        var filter = args.FirstOrDefault();
        var tests = typeof(Runner).Assembly.GetTypes()
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .Where(m => m.GetCustomAttribute<TestAttribute>() is not null)
                .Select(m => (Type: t, Method: m)))
            .Where(x => filter is null || $"{x.Type.Name}.{x.Method.Name}".Contains(filter, StringComparison.OrdinalIgnoreCase))
            .OrderBy(x => x.Type.Name).ThenBy(x => x.Method.Name)
            .ToList();

        var failed = 0;
        foreach (var (type, method) in tests)
        {
            var name = $"{type.Name}.{method.Name}";
            var watch = Stopwatch.StartNew();
            object? instance = null;
            try
            {
                instance = Activator.CreateInstance(type)!;
                if (method.Invoke(instance, null) is Task task)
                {
                    await task.WaitAsync(TimeSpan.FromSeconds(60));
                }
                Console.WriteLine($"PASS {name} ({watch.ElapsedMilliseconds} ms)");
            }
            catch (Exception ex)
            {
                failed++;
                var inner = ex is TargetInvocationException { InnerException: { } i } ? i : ex;
                Console.WriteLine($"FAIL {name}: {inner.GetType().Name}: {inner.Message}");
                if (inner is not AssertFailedException)
                {
                    Console.WriteLine(inner.StackTrace);
                }
            }
            finally
            {
                (instance as IDisposable)?.Dispose();
            }
        }
        Console.WriteLine($"{tests.Count - failed}/{tests.Count} passed.");
        return failed == 0 && tests.Count > 0 ? 0 : 1;
    }
}
