using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace TownSuite.CodeSigning.Service
{
    public record ServiceStatus(
        string Name,
        string Version,
        string Environment,
        string MachineName,
        DateTimeOffset ProcessStartTimeUtc,
        double UptimeSeconds);

    public record QueueStatus(
        int Depth,
        int InFlight,
        long Completed,
        long Failed,
        bool WorkerRunning,
        DateTimeOffset? LastActivityUtc,
        double? SecondsSinceLastActivity);

    public record ConcurrencyStatus(
        int? MaxSlots,
        int? AvailableSlots,
        int? InUse);

    public record HealthCheckEntryStatus(
        string Name,
        string Status,
        string? Description,
        double DurationMs);

    public record HealthStatusDto(
        string Status,
        double TotalDurationMs,
        IReadOnlyList<HealthCheckEntryStatus> Checks);

    public record CertificateStatus(
        string Role,
        string? File,
        string? Subject,
        string? Thumbprint,
        DateTimeOffset? NotBefore,
        DateTimeOffset? NotAfter,
        double? DaysUntilExpiry,
        string State,
        string? Error);

    public record BatchStatus(
        string TempFolder,
        int? PendingJobFolders);

    public record StatusResponse(
        DateTimeOffset TimestampUtc,
        ServiceStatus Service,
        QueueStatus Queue,
        ConcurrencyStatus Concurrency,
        HealthStatusDto? Health,
        IReadOnlyList<CertificateStatus> Certificates,
        BatchStatus Batch);

    public class StatusService
    {
        private static readonly TimeSpan CertCacheTtl = TimeSpan.FromSeconds(60);

        private readonly Settings _settings;
        private readonly ILogger _logger;
        private readonly BackgroundQueue _queue;
        private readonly DateTimeOffset _processStartTimeUtc = Process.GetCurrentProcess().StartTime.ToUniversalTime();

        private readonly ConcurrentDictionary<string, (CertificateStatus Info, DateTimeOffset LoadedAt)> _certCache = new();

        public StatusService(Settings settings, ILogger logger)
            : this(settings, logger, BackgroundQueue.Instance)
        {
        }

        public StatusService(Settings settings, ILogger logger, BackgroundQueue queue)
        {
            _settings = settings;
            _logger = logger;
            _queue = queue;
        }

        public async Task<StatusResponse> GetStatusAsync(HealthCheckService? healthService, CancellationToken cancellationToken)
        {
            return new StatusResponse(
                DateTimeOffset.UtcNow,
                BuildServiceStatus(),
                BuildQueueStatus(),
                BuildConcurrencyStatus(),
                await BuildHealthStatusAsync(healthService, cancellationToken),
                BuildCertificateStatuses(),
                BuildBatchStatus());
        }

        private ServiceStatus BuildServiceStatus()
        {
            var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "unknown";
            var environment = System.Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production";
            var now = DateTimeOffset.UtcNow;

            return new ServiceStatus(
                "TownSuite.CodeSigning.Service",
                version,
                environment,
                System.Environment.MachineName,
                _processStartTimeUtc,
                (now - _processStartTimeUtc).TotalSeconds);
        }

        private QueueStatus BuildQueueStatus()
        {
            var lastActivity = _queue.LastActivityUtc;
            double? secondsSinceLastActivity = lastActivity.HasValue
                ? (DateTimeOffset.UtcNow - lastActivity.Value).TotalSeconds
                : null;

            return new QueueStatus(
                _queue.QueueDepth,
                _queue.InFlight,
                _queue.CompletedCount,
                _queue.FailedCount,
                _queue.IsWorkerRunning,
                lastActivity,
                secondsSinceLastActivity);
        }

        private ConcurrencyStatus BuildConcurrencyStatus()
        {
            try
            {
                int maxSlots = System.Environment.ProcessorCount * _settings.SemaphoreSlimProcessPerCpuLimit;
                int availableSlots = Queuing.Semaphore.CurrentCount;
                return new ConcurrencyStatus(maxSlots, availableSlots, maxSlots - availableSlots);
            }
            catch (InvalidOperationException)
            {
                // Semaphore not initialized yet.
                return new ConcurrencyStatus(null, null, null);
            }
        }

        private async Task<HealthStatusDto?> BuildHealthStatusAsync(HealthCheckService? healthService, CancellationToken cancellationToken)
        {
            if (healthService == null)
            {
                return null;
            }

            var report = await healthService.CheckHealthAsync(cancellationToken);
            var checks = report.Entries
                .Select(e => new HealthCheckEntryStatus(
                    e.Key,
                    e.Value.Status.ToString(),
                    e.Value.Description,
                    e.Value.Duration.TotalMilliseconds))
                .ToList();

            return new HealthStatusDto(report.Status.ToString(), report.TotalDuration.TotalMilliseconds, checks);
        }

        private IReadOnlyList<CertificateStatus> BuildCertificateStatuses()
        {
            var results = new List<CertificateStatus>();

            if (!string.IsNullOrWhiteSpace(_settings.CertificatePath))
            {
                results.Add(GetOrLoadCertificateStatus("signtool", _settings.CertificatePath, _settings.CertificatePassword));
            }

            if (!string.IsNullOrWhiteSpace(_settings.OpenSSL?.SignerCertPath))
            {
                results.Add(GetOrLoadCertificateStatus("openssl-detached", _settings.OpenSSL.SignerCertPath, null));
            }

            return results;
        }

        private CertificateStatus GetOrLoadCertificateStatus(string role, string configuredPath, string? password)
        {
            var resolvedPath = configuredPath.Replace("{BaseDirectory}", AppContext.BaseDirectory + Path.DirectorySeparatorChar);

            if (_certCache.TryGetValue(resolvedPath, out var cached) && DateTimeOffset.UtcNow - cached.LoadedAt < CertCacheTtl)
            {
                return RefreshExpiryState(cached.Info);
            }

            var info = LoadCertificateStatus(role, resolvedPath, password);
            _certCache[resolvedPath] = (info, DateTimeOffset.UtcNow);
            return info;
        }

        private CertificateStatus RefreshExpiryState(CertificateStatus cached)
        {
            if (cached.NotAfter == null || cached.State == "error")
            {
                return cached;
            }

            var warningDays = _settings.CertificateWarningDays > 0 ? _settings.CertificateWarningDays : 30;
            var now = DateTimeOffset.UtcNow;
            var daysUntilExpiry = (cached.NotAfter.Value - now).TotalDays;
            var state = ComputeState(cached.NotAfter.Value, warningDays, now);
            return cached with { DaysUntilExpiry = daysUntilExpiry, State = state };
        }

        private CertificateStatus LoadCertificateStatus(string role, string resolvedPath, string? password)
        {
            var fileName = Path.GetFileName(resolvedPath);
            try
            {
                using var cert = LoadCertificate(resolvedPath, password);

                var warningDays = _settings.CertificateWarningDays > 0 ? _settings.CertificateWarningDays : 30;
                var now = DateTimeOffset.UtcNow;
                var notAfter = new DateTimeOffset(cert.NotAfter.ToUniversalTime());
                var notBefore = new DateTimeOffset(cert.NotBefore.ToUniversalTime());
                var daysUntilExpiry = (notAfter - now).TotalDays;
                var state = ComputeState(notAfter, warningDays, now);

                return new CertificateStatus(
                    role,
                    fileName,
                    cert.Subject,
                    cert.Thumbprint,
                    notBefore,
                    notAfter,
                    daysUntilExpiry,
                    state,
                    null);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, $"Failed to load certificate for admin status ({role}): {resolvedPath}");
                return new CertificateStatus(role, fileName, null, null, null, null, null, "error", ex.Message);
            }
        }

        private static X509Certificate2 LoadCertificate(string path, string? password)
        {
            var extension = Path.GetExtension(path).ToLowerInvariant();
            if (extension is ".pfx" or ".p12")
            {
                return X509CertificateLoader.LoadPkcs12FromFile(path, password);
            }

            try
            {
                return X509CertificateLoader.LoadCertificateFromFile(path);
            }
            catch when (!string.IsNullOrEmpty(password))
            {
                return X509CertificateLoader.LoadPkcs12FromFile(path, password);
            }
        }

        public static string ComputeState(DateTimeOffset notAfter, int warningDays, DateTimeOffset now)
        {
            if (notAfter <= now)
            {
                return "expired";
            }

            if ((notAfter - now).TotalDays <= warningDays)
            {
                return "warning";
            }

            return "ok";
        }

        private BatchStatus BuildBatchStatus()
        {
            var tempFolder = BatchedSigning.GetTempFolder();
            int? pendingJobFolders;
            try
            {
                pendingJobFolders = Directory.Exists(tempFolder)
                    ? Directory.EnumerateDirectories(tempFolder).Count(d => !string.Equals(Path.GetFileName(d), SigningHealthCheck.CanaryFolderName, StringComparison.OrdinalIgnoreCase))
                    : 0;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to enumerate batch working folder for admin status");
                pendingJobFolders = null;
            }

            return new BatchStatus(tempFolder, pendingJobFolders);
        }
    }
}
