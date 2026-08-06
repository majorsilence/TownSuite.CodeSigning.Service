namespace TownSuite.CodeSigning.Service
{
    /// <summary>
    /// Re-runs the signing canary out of band so /healthz, /health/ready and /admin/status can
    /// answer from the last published result instead of waiting on signtool, which shells out to
    /// the timestamp server and can take seconds or stall until its timeout.
    ///
    /// Refreshes on <see cref="SigningHealthCheck.RefreshInterval"/> (Settings.HealthCheckCacheInMs).
    /// </summary>
    public class SigningCanaryService : BackgroundService
    {
        private readonly SigningHealthCheck _healthCheck;
        private readonly ILogger _logger;

        public SigningCanaryService(SigningHealthCheck healthCheck, ILogger logger)
        {
            _healthCheck = healthCheck;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Yield before touching signtool so the first canary run never delays host startup.
            await Task.Yield();

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await _healthCheck.RefreshAsync(stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    // The refresher has to outlive any single failure. If this loop exits, the
                    // canary result goes stale forever and readiness stops reflecting reality
                    // (SigningHealthCheck reports the staleness rather than a false Healthy).
                    _logger.LogError(ex, "Signing canary refresh failed");
                }

                try
                {
                    await Task.Delay(_healthCheck.RefreshInterval, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
    }
}
