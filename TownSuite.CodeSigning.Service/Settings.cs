namespace TownSuite.CodeSigning.Service
{
    public class Settings
    {
        public string SignToolPath { get; init; }
        public string SignToolOptions { get; init; }
        public int SigntoolTimeoutInMs { get; init; }
        /// <summary>
        /// bytes
        /// </summary>
        public long MaxRequestBodySize { get; init; }
        public int SemaphoreSlimProcessPerCpuLimit { get; init; }

        /// <summary>
        /// How often (in milliseconds) the readiness signing canary re-runs signtool in the
        /// background. Probes never run signtool themselves; they read the most recent result, so
        /// this controls how quickly a signing failure is noticed, not how fast probes respond.
        /// A result older than three intervals is reported as stale. Defaults to 30000 when unset
        /// (0 or negative).
        /// </summary>
        public int HealthCheckCacheInMs { get; init; }

        /// <summary>
        /// Readiness fails if the signing queue has pending jobs but the background worker has
        /// not finished a job within this many milliseconds (i.e. the queue is not draining).
        /// Defaults to 60000 when unset (0 or negative). Should comfortably exceed
        /// <see cref="SigntoolTimeoutInMs"/> so normal per-job time is not flagged as a stall.
        /// </summary>
        public int HealthCheckQueueStallInMs { get; init; }

        public OpenSSLSettings OpenSSL { get; init; }

        /// <summary>
        /// Path to the signtool certificate (.pfx/.p12 or .crt/.cer/.pem) to inspect for the admin
        /// status dashboard. Supports the {BaseDirectory} placeholder. Cert reporting is skipped
        /// when unset.
        /// </summary>
        public string? CertificatePath { get; init; }

        /// <summary>
        /// Password for <see cref="CertificatePath"/> when it is a .pfx/.p12 file. Not needed for
        /// public-only formats (.crt/.cer/.pem).
        /// </summary>
        public string? CertificatePassword { get; init; }

        /// <summary>
        /// Number of days before certificate expiry at which the admin status dashboard reports a
        /// "warning" state instead of "ok". Defaults to 30 when unset (0 or negative).
        /// </summary>
        public int CertificateWarningDays { get; init; }

    }

    public class OpenSSLSettings
    {
        /// <summary>
        /// Path to the openssl executable to use for detached signing. Supports {BaseDirectory} placeholder.
        /// </summary>
        public string OpenSslPath { get; init; }

        /// <summary>
        /// Full openssl cms command arguments template. Supports placeholders:
        /// {InputFilePath}, {SignerPem}, {SignatureFilePath}.
        /// </summary>
        public string OpenSslOptions { get; init; }

        /// <summary>
        /// Timeout in milliseconds for openssl process invocations.
        /// </summary>
        public int OpenSslTimeoutInMs { get; init; }

        public string OsslSignCodePath { get; init; }
        public string TimestampOptions { get; init; }

        /// <summary>
        /// Path to the public signer certificate (.crt/.cer/.pem, or .pfx/.p12) used for detached
        /// signing, inspected for the admin status dashboard. Supports {BaseDirectory}. Cert
        /// reporting is skipped when unset.
        /// </summary>
        public string? SignerCertPath { get; init; }
    }
}
