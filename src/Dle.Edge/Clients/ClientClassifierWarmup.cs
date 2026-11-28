using System.Diagnostics.CodeAnalysis;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Dle.Edge.Clients;

/// <summary>
/// Makes the classifier compile its regular expressions before the server takes a request.
/// </summary>
/// <remarks>
/// Hosted services start before Kestrel listens, so no visitor waits for this, and the first real
/// request neither pays for it nor gets an answer the parser could not finish. A classifier a
/// deployment registered itself is left alone: only this one is known to have anything to warm.
/// </remarks>
internal sealed partial class ClientClassifierWarmup(
    IClientClassifier classifier,
    ILogger<ClientClassifierWarmup> logger) : IHostedService
{
    /// <inheritdoc />
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Warming up is an optimisation and a failure must not keep the edge from starting. A parser that " +
                        "cannot be built fails every request either way, as it did before; any other failure leaves the " +
                        "first requests to pay for compiling. Cancellation still stops the start.")]
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (classifier is not ClientClassifier own)
        {
            return;
        }

        long started = TimeProvider.System.GetTimestamp();

        try
        {
            // On a thread pool thread: the work is one long synchronous burst, and the host should be
            // able to observe its own cancellation.
            await Task.Run(() => own.WarmUp(cancellationToken), cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            WarmUpFailed(logger, exception);
            return;
        }

        TimeSpan elapsed = TimeProvider.System.GetElapsedTime(started);
        WarmedUp(logger, elapsed.TotalMilliseconds);
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    [LoggerMessage(
        EventId = 1032,
        Level = LogLevel.Information,
        Message = "The user agent classifier compiled its expressions in {ElapsedMilliseconds:F0} ms, before the first request.")]
    private static partial void WarmedUp(ILogger logger, double elapsedMilliseconds);

    [LoggerMessage(
        EventId = 1033,
        Level = LogLevel.Warning,
        Message = "Warming up the user agent classifier failed; the first requests pay for compiling it instead.")]
    private static partial void WarmUpFailed(ILogger logger, Exception exception);
}
