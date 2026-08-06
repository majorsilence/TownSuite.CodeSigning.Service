using Microsoft.Extensions.Diagnostics.HealthChecks;
using System.Reflection;

namespace TownSuite.CodeSigning.Service
{
    /// <summary>
    /// Readiness health check with two signals. Both are answered from memory so probes return
    /// immediately: nothing on this path waits on signtool, the filesystem or the network.
    ///
    /// 1. A signing canary: signs a throwaway copy of a real PE file with the configured
    ///    signtool settings. If signing fails (for example
    ///    "SignTool Error: No private key is available.") the service is reported unhealthy.
    ///    signtool shells out and contacts the timestamp server, which takes seconds and can
    ///    stall outright, so it is never run inside a probe request. <see cref="SigningCanaryService"/>
    ///    calls <see cref="RefreshAsync"/> on a timer and <see cref="CheckHealthAsync"/> only
    ///    reads the last published result.
    ///
    /// 2. A queue-drain check: batch signing runs asynchronously on <see cref="BackgroundQueue"/>,
    ///    so signtool passing the canary does not prove queued jobs are being processed. If the
    ///    queue has pending jobs but the worker has not completed one within the configured stall
    ///    window, the service is reported unhealthy. This signal is cheap and evaluated live.
    /// </summary>
    public class SigningHealthCheck : IHealthCheck
    {
        /// <summary>
        /// A canary result older than this many refresh intervals is treated as stale: it means the
        /// background refresher stopped running, so the last result no longer describes reality.
        /// </summary>
        private const int StaleAfterIntervals = 3;

        private readonly Settings _settings;
        private readonly ILogger _logger;
        private readonly BackgroundQueue _queue;

        // Collapses overlapping refreshes; never waited on by a request thread.
        private readonly SemaphoreSlim _refreshGate = new SemaphoreSlim(1, 1);

        // Single reference swap so readers always see a result and its timestamp together.
        private volatile CanarySnapshot _snapshot;

        private sealed record CanarySnapshot(HealthCheckResult Result, DateTimeOffset CompletedAt);

        public SigningHealthCheck(Settings settings, ILogger logger)
            : this(settings, logger, BackgroundQueue.Instance)
        {
        }

        public SigningHealthCheck(Settings settings, ILogger logger, BackgroundQueue queue)
        {
            _settings = settings;
            _logger = logger;
            _queue = queue;
        }

        /// <summary>
        /// How often the background canary re-runs signtool.
        /// </summary>
        public TimeSpan RefreshInterval =>
            TimeSpan.FromMilliseconds(_settings.HealthCheckCacheInMs > 0 ? _settings.HealthCheckCacheInMs : 30000);

        private TimeSpan StaleAfter => RefreshInterval * StaleAfterIntervals;

        private TimeSpan QueueStallWindow =>
            TimeSpan.FromMilliseconds(_settings.HealthCheckQueueStallInMs > 0 ? _settings.HealthCheckQueueStallInMs : 60000);

        /// <summary>
        /// Returns the current readiness verdict without blocking. Deliberately synchronous work
        /// only — see the class remarks.
        /// </summary>
        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context,
            CancellationToken cancellationToken = default)
        {
            var queueResult = CheckQueueDraining();
            if (queueResult.Status == HealthStatus.Unhealthy)
            {
                return Task.FromResult(queueResult);
            }

            return Task.FromResult(ReadCanaryResult());
        }

        /// <summary>
        /// Runs the signing canary and publishes the result for <see cref="CheckHealthAsync"/> to
        /// read. Called on a timer by <see cref="SigningCanaryService"/>, and directly by tests.
        /// If a run is already in progress this returns immediately rather than queueing behind it.
        /// </summary>
        public async Task RefreshAsync(CancellationToken cancellationToken = default)
        {
            if (!await _refreshGate.WaitAsync(0, cancellationToken))
            {
                return;
            }

            try
            {
                var result = await RunSignCanaryAsync();
                _snapshot = new CanarySnapshot(result, DateTimeOffset.UtcNow);
            }
            finally
            {
                _refreshGate.Release();
            }
        }

        private HealthCheckResult ReadCanaryResult()
        {
            var snapshot = _snapshot;
            if (snapshot == null)
            {
                // Degraded rather than Unhealthy: a probe that lands before the first canary run
                // finishes should not fail the container during startup. Degraded still returns 200.
                return HealthCheckResult.Degraded("Code signing canary has not completed a run yet.");
            }

            // A failing canary stays failing until a later run says otherwise.
            if (snapshot.Result.Status == HealthStatus.Unhealthy)
            {
                return snapshot.Result;
            }

            var age = DateTimeOffset.UtcNow - snapshot.CompletedAt;
            if (age > StaleAfter)
            {
                var message =
                    $"Code signing canary result is stale: {age.TotalSeconds:n0}s old, " +
                    $"refresh interval {RefreshInterval.TotalSeconds:n0}s. " +
                    $"Last known result: {snapshot.Result.Description}";
                _logger.LogError(message);
                return HealthCheckResult.Degraded(message);
            }

            return snapshot.Result;
        }

        private HealthCheckResult CheckQueueDraining()
        {
            var queue = _queue;
            int depth = queue.QueueDepth;
            if (depth == 0)
            {
                // Nothing waiting; the queue is fully drained regardless of timing.
                return HealthCheckResult.Healthy("Signing queue is drained.");
            }

            var lastActivity = queue.LastActivityUtc;
            if (lastActivity.HasValue)
            {
                var idle = DateTimeOffset.UtcNow - lastActivity.Value;
                if (idle > QueueStallWindow)
                {
                    var message =
                        $"Signing queue is not draining: {depth} job(s) pending, {queue.InFlight} in flight, " +
                        $"no job completed for {idle.TotalSeconds:n0}s (stall window {QueueStallWindow.TotalSeconds:n0}s).";
                    _logger.LogError(message);
                    return HealthCheckResult.Unhealthy(message);
                }
            }

            return HealthCheckResult.Healthy($"Signing queue is draining ({depth} pending).");
        }

        private async Task<HealthCheckResult> RunSignCanaryAsync()
        {
            var workingFolder = new DirectoryInfo(Path.Combine(BatchedSigning.GetTempFolder(), "healthcheck"));
            var canaryPath = Path.Combine(workingFolder.FullName, $"healthcheck-{Guid.NewGuid()}.dll");
            try
            {
                workingFolder.CreateIfNotExists();

                // Sign a throwaway copy of a real PE file (this assembly) so signtool exercises
                // the full signing path including access to the private key.
                var source = Assembly.GetExecutingAssembly().Location;
                File.Copy(source, canaryPath, true);

                var signer = new Signer(_settings, _logger);
                var result = await signer.SignAsync(workingFolder.FullName, new[] { canaryPath });

                if (result.IsSigned)
                {
                    return HealthCheckResult.Healthy("Code signing is operational.");
                }

                _logger.LogError($"Readiness signing canary failed: {result.Message}");
                return HealthCheckResult.Unhealthy($"Code signing is failing. {result.Message}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Readiness signing canary threw an exception");
                return HealthCheckResult.Unhealthy("Code signing is failing.", ex);
            }
            finally
            {
                try
                {
                    if (File.Exists(canaryPath))
                    {
                        File.Delete(canaryPath);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogInformation($"Failed to cleanup health check canary {canaryPath}: {ex.Message}");
                }
            }
        }
    }
}
