using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

using Dle.Domain.Clients;
using Dle.Domain.Ports;
using Dle.Edge.Clients;
using Dle.Edge.Configuration;
using Dle.Edge.Resolution;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Xunit;

namespace Dle.UnitTests.Edge;

/// <summary>
/// The user agent parser gives up on a regular expression that runs past its timeout and answers as
/// if it had not matched. It does that while the expressions are being compiled after start-up, and
/// whenever the coarse clock the timeout is measured with steps during a match. These tests pin what
/// may be kept from such a parse, and that the edge compiles the expressions before its first request.
/// </summary>
public sealed class ClientClassifierColdStartTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 8, 0, 0, TimeSpan.Zero);
    private static readonly UserAgentFacts Wrong = new() { UaFamily = "Mobile Safari UI/WKWebView" };
    private static readonly UserAgentFacts Right = new() { UaFamily = "Mobile Safari" };

    [Fact]
    public void ACleanParse_IsMemoised_AfterOneParse()
    {
        var parser = new ScriptedParser(new Step(Right));
        ClientClassifier classifier = parser.CreateClassifier();

        Assert.Equal("Mobile Safari", Family(classifier, "ua"));
        Assert.Equal("Mobile Safari", Family(classifier, "ua"));

        Assert.Equal(1, parser.Calls);
    }

    [Fact]
    public void AParseThatDroppedAnExpression_IsParsedAgain_AndOnlyTheCleanAnswerIsKept()
    {
        // The drop does not depend on how long the whole parse took: a fast parse loses a match just
        // the same when the clock steps during one expression.
        var parser = new ScriptedParser(new Step(Wrong, Drops: true), new Step(Right));
        ClientClassifier classifier = parser.CreateClassifier();

        Assert.Equal("Mobile Safari", Family(classifier, "ua"));
        Assert.Equal(2, parser.Calls);

        Assert.Equal("Mobile Safari", Family(classifier, "ua"));
        Assert.Equal(2, parser.Calls);
    }

    [Fact]
    public void AnAnswerThatDroppedTwice_IsUsed_ButNotKept()
    {
        var parser = new ScriptedParser(
            new Step(Wrong, Drops: true),
            new Step(Wrong, Drops: true),
            new Step(Right));
        ClientClassifier classifier = parser.CreateClassifier();

        Assert.Equal("Mobile Safari UI/WKWebView", Family(classifier, "ua"));
        Assert.Equal(2, parser.Calls);

        // Nothing was kept, so the next request parses again and keeps the clean answer.
        Assert.Equal("Mobile Safari", Family(classifier, "ua"));
        Assert.Equal(3, parser.Calls);
        Assert.Equal("Mobile Safari", Family(classifier, "ua"));
        Assert.Equal(3, parser.Calls);
    }

    [Fact]
    public void WarmUp_ParsesRealAndUnmatchableInput_AndKeepsNothing()
    {
        var parser = new ScriptedParser(new Step(Right));
        ClientClassifier classifier = parser.CreateClassifier();

        classifier.WarmUp(CancellationToken.None);

        int warmed = parser.Calls;
        Assert.Contains(parser.Seen, ua => ua.Contains("iPhone", StringComparison.Ordinal));
        Assert.Contains(parser.Seen, ua => ua.Contains("Android", StringComparison.Ordinal));
        Assert.Contains(parser.Seen, ua => !ua.Contains("Mozilla", StringComparison.Ordinal) && ua.Length >= 512);

        // An answer reached while the cascade was compiling must not outlive the warm-up.
        _ = Family(classifier, parser.Seen[0]);
        Assert.Equal(warmed + 1, parser.Calls);
    }

    [Fact]
    public void WarmUp_StopsWhenStartupIsCancelled()
    {
        var parser = new ScriptedParser(new Step(Right));
        ClientClassifier classifier = parser.CreateClassifier();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        Assert.Throws<OperationCanceledException>(() => classifier.WarmUp(cancelled.Token));
        Assert.Equal(0, parser.Calls);
    }

    [Fact]
    public async Task TheHostedService_WarmsTheClassifier()
    {
        var parser = new ScriptedParser(new Step(Right));
        ClientClassifier classifier = parser.CreateClassifier();
        var logger = new CollectingLogger();

        await new ClientClassifierWarmup(classifier, logger).StartAsync(TestContext.Current.CancellationToken);

        Assert.True(parser.Calls > 0);
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Information);
    }

    [Fact]
    public async Task TheHostedService_DoesNotStopStartup_WhenWarmUpFails()
    {
        var parser = new ScriptedParser(new InvalidOperationException("the parser broke"));
        ClientClassifier classifier = parser.CreateClassifier();
        var logger = new CollectingLogger();

        await new ClientClassifierWarmup(classifier, logger).StartAsync(TestContext.Current.CancellationToken);

        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Warning && entry.Exception is not null);
    }

    [Fact]
    public async Task TheHostedService_LeavesAForeignClassifierAlone()
    {
        var logger = new CollectingLogger();

        await new ClientClassifierWarmup(new ForeignClassifier(), logger).StartAsync(TestContext.Current.CancellationToken);

        Assert.Empty(logger.Entries);
    }

    [Fact]
    public void TheEdge_RegistersTheWarmUp()
    {
        var services = new ServiceCollection();

        services.AddDleEdgeCore(new ConfigurationBuilder().Build());

        Assert.Contains(
            services,
            descriptor => descriptor.ServiceType == typeof(IHostedService)
                && descriptor.ImplementationType == typeof(ClientClassifierWarmup));
    }

    private static string? Family(ClientClassifier classifier, string userAgent) =>
        classifier.Classify(new ClientRequest
        {
            Host = "link.example.test",
            Path = "/abc",
            UserAgent = userAgent,
            Query = ReadOnlyDictionary<string, string>.Empty,
            ReceivedAt = Now,
        }).UaFamily;

    /// <summary>One answer of the scripted parser, and whether the parse dropped an expression.</summary>
    private sealed record Step(UserAgentFacts Answer, bool Drops = false);

    /// <summary>A parser whose answers, and whose dropped expressions, the test decides.</summary>
    private sealed class ScriptedParser
    {
        private readonly Step[] _steps;
        private readonly Exception? _failure;

        internal ScriptedParser(params Step[] steps) => _steps = steps;

        internal ScriptedParser(Exception failure)
        {
            _steps = [];
            _failure = failure;
        }

        internal int Calls { get; private set; }

        internal List<string> Seen { get; } = [];

        internal ClientClassifier CreateClassifier() =>
            new(NullGeoIpResolver.Instance, Options.Create(new EdgeOptions()), Parse);

        private UserAgentFacts Parse(string userAgent)
        {
            Calls++;
            Seen.Add(userAgent);

            if (_failure is not null)
            {
                throw _failure;
            }

            Step step = _steps[Math.Min(Calls - 1, _steps.Length - 1)];

            if (step.Drops)
            {
                DropAnExpression();
            }

            return step.Answer;
        }

        /// <summary>What the real parser does when an expression times out: throws and swallows it.</summary>
        private static void DropAnExpression()
        {
            try
            {
                throw new RegexMatchTimeoutException("ua", "pattern", TimeSpan.FromMilliseconds(5));
            }
            catch (RegexMatchTimeoutException)
            {
            }
        }
    }

    private sealed class ForeignClassifier : IClientClassifier
    {
        public ClientContext Classify(ClientRequest request) => throw new NotSupportedException();
    }

    private sealed class CollectingLogger : ILogger<ClientClassifierWarmup>
    {
        internal List<(LogLevel Level, Exception? Exception)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) => Entries.Add((logLevel, exception));
    }
}
