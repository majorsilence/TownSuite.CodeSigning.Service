using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Threading.Tasks;
using TownSuite.CodeSigning.Service;

namespace TownSuite.CodeSigning.Tests
{
    [TestFixture]
    public class SignerDetachedTimeoutTest
    {
        // A stand-in for a wedged openssl: appends one line per second for a minute, far longer
        // than the timeout below. The marker file is what lets the test see whether it was killed.
        private const string TickerCommand =
            "/c for /L %i in (1,1,60) do @(echo tick>>marker.txt & ping -n 2 127.0.0.1 >nul)";

        private const int TimeoutMs = 1500;

        private static Settings TickerSettings()
        {
            var good = OneTimeUnitTestSetup.SignToolSettings!;
            return new Settings
            {
                SignToolPath = good.SignToolPath,
                SignToolOptions = good.SignToolOptions,
                // SignerDetached times its openssl invocations off SigntoolTimeoutInMs.
                SigntoolTimeoutInMs = TimeoutMs,
                MaxRequestBodySize = good.MaxRequestBodySize,
                SemaphoreSlimProcessPerCpuLimit = good.SemaphoreSlimProcessPerCpuLimit,
                HealthCheckCacheInMs = good.HealthCheckCacheInMs,
                HealthCheckQueueStallInMs = good.HealthCheckQueueStallInMs,
                OpenSSL = new OpenSSLSettings
                {
                    OpenSslPath = "cmd.exe",
                    OpenSslOptions = TickerCommand,
                    OpenSslTimeoutInMs = good.OpenSSL.OpenSslTimeoutInMs,
                    // Timestamping off, so this exercises the signing timeout on its own.
                    OsslSignCodePath = "",
                    TimestampOptions = "",
                    SignerCertPath = null,
                }
            };
        }

        [Test]
        [Platform("Win")]
        public async Task Timeout_KillsTheProcessTree_AndReportsFailure()
        {
            // Regression: WaitForExitAsync throws on cancellation, so the
            // "if (IsCancellationRequested)" block that followed it was unreachable. A timeout
            // neither reported failure nor killed the process, so every timeout left a wedged
            // openssl/osslsigncode running and leaked its handles.
            var workingDir = Path.Combine(Path.GetTempPath(), "townsuite-detached-timeout-" + Guid.NewGuid());
            Directory.CreateDirectory(workingDir);
            var marker = Path.Combine(workingDir, "marker.txt");

            try
            {
                var signer = new SignerDetached(TickerSettings(), NSubstitute.Substitute.For<ILogger>());

                var sw = System.Diagnostics.Stopwatch.StartNew();
                var result = await signer.SignAsync(workingDir, new[] { "unused" });
                sw.Stop();

                Assert.Multiple(() =>
                {
                    Assert.That(result.IsSigned, Is.False, "a timeout must not report success");
                    Assert.That(result.Message, Does.Contain("timeout reached"));
                    Assert.That(sw.ElapsedMilliseconds, Is.LessThan(20000),
                        "SignAsync should return at its timeout, not wait for the child to finish");
                });

                // The child ticks once a second. Killed, the marker stops growing; leaked, it keeps
                // being appended to.
                await Task.Delay(2500);
                long first = FileLength(marker);
                await Task.Delay(2500);
                long second = FileLength(marker);

                Assert.That(second, Is.EqualTo(first),
                    $"marker grew from {first} to {second} bytes after the timeout, so the process tree was not killed");
            }
            finally
            {
                try { Directory.Delete(workingDir, true); } catch { /* a leaked child holds marker.txt open */ }
            }
        }

        private static long FileLength(string path)
        {
            var info = new FileInfo(path);
            return info.Exists ? info.Length : 0;
        }
    }
}
