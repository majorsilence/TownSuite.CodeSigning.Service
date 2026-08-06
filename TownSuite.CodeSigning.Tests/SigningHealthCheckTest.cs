using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using System.Threading;
using TownSuite.CodeSigning.Service;

namespace TownSuite.CodeSigning.Tests
{
    [TestFixture]
    public class SigningHealthCheckTest
    {
        private static HealthCheckContext Context() => new HealthCheckContext
        {
            Registration = new HealthCheckRegistration("signing",
                _ => throw new NotImplementedException(), HealthStatus.Unhealthy, new[] { "ready" })
        };

        [Test]
        public async Task Ready_IsHealthy_WhenSigningWorks()
        {
            var settings = OneTimeUnitTestSetup.SignToolSettings!;
            var check = new SigningHealthCheck(settings, NSubstitute.Substitute.For<ILogger>());

            await check.RefreshAsync();
            var result = await check.CheckHealthAsync(Context());

            Assert.That(result.Status, Is.EqualTo(HealthStatus.Healthy), result.Description);
        }

        [Test]
        public async Task Ready_IsDegraded_BeforeTheFirstCanaryRun()
        {
            // Probes that land during startup must not fail the container, and must not block
            // waiting for the first canary either.
            var settings = OneTimeUnitTestSetup.SignToolSettings!;
            var check = new SigningHealthCheck(settings, NSubstitute.Substitute.For<ILogger>());

            var result = await check.CheckHealthAsync(Context());

            Assert.Multiple(() =>
            {
                Assert.That(result.Status, Is.EqualTo(HealthStatus.Degraded));
                Assert.That(result.Description, Does.Contain("has not completed a run yet"));
            });
        }

        [Test]
        public async Task Ready_DoesNotRunSigntool_OnTheProbePath()
        {
            // The regression this guards: signtool was invoked inline, so /healthz and
            // /admin/status blocked on a timestamp server round trip (up to SigntoolTimeoutInMs).
            var good = OneTimeUnitTestSetup.SignToolSettings!;
            var check = new SigningHealthCheck(good, NSubstitute.Substitute.For<ILogger>());
            await check.RefreshAsync();

            var sw = System.Diagnostics.Stopwatch.StartNew();
            for (int i = 0; i < 50; i++)
            {
                await check.CheckHealthAsync(Context());
            }
            sw.Stop();

            Assert.That(sw.ElapsedMilliseconds, Is.LessThan(100),
                $"50 probes took {sw.ElapsedMilliseconds}ms; the probe path is doing real work.");
        }

        [Test]
        public async Task Ready_RepeatedUnhealthyProbes_DoNotReRunSigntool()
        {
            // A failing canary used to bypass the cache entirely, so every probe paid for a full
            // signtool invocation and concurrent probes serialized behind each other.
            var check = new SigningHealthCheck(BrokenCertSettings(), NSubstitute.Substitute.For<ILogger>());
            await check.RefreshAsync();

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var results = new List<HealthCheckResult>();
            for (int i = 0; i < 25; i++)
            {
                results.Add(await check.CheckHealthAsync(Context()));
            }
            sw.Stop();

            Assert.Multiple(() =>
            {
                Assert.That(results, Is.All.Matches<HealthCheckResult>(r => r.Status == HealthStatus.Unhealthy));
                Assert.That(sw.ElapsedMilliseconds, Is.LessThan(100),
                    $"25 unhealthy probes took {sw.ElapsedMilliseconds}ms; signtool is still being re-run.");
            });
        }

        [Test]
        public async Task Refresh_IsSkipped_WhileAnotherRefreshIsInFlight()
        {
            // Overlapping refreshes collapse instead of queueing, so a slow signtool cannot pile up.
            var settings = OneTimeUnitTestSetup.SignToolSettings!;
            var check = new SigningHealthCheck(settings, NSubstitute.Substitute.For<ILogger>());

            await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => check.RefreshAsync()));

            var result = await check.CheckHealthAsync(Context());
            Assert.That(result.Status, Is.EqualTo(HealthStatus.Healthy), result.Description);
        }

        private static Settings WithStallWindow(int stallMs)
        {
            var good = OneTimeUnitTestSetup.SignToolSettings!;
            return new Settings
            {
                SignToolPath = good.SignToolPath,
                SignToolOptions = good.SignToolOptions,
                SigntoolTimeoutInMs = good.SigntoolTimeoutInMs,
                MaxRequestBodySize = good.MaxRequestBodySize,
                SemaphoreSlimProcessPerCpuLimit = good.SemaphoreSlimProcessPerCpuLimit,
                HealthCheckCacheInMs = good.HealthCheckCacheInMs,
                HealthCheckQueueStallInMs = stallMs,
                OpenSSL = good.OpenSSL
            };
        }

        [Test]
        public async Task Ready_IsUnhealthy_WhenSigningQueueIsNotDraining()
        {
            // A blocked worker with jobs still queued behind it simulates a wedged signing queue.
            var queue = new BackgroundQueue();
            using var gate = new ManualResetEventSlim(false);
            queue.QueueThread(() => gate.Wait());   // in-flight, blocks the worker
            queue.QueueThread(() => { });           // stays queued -> QueueDepth > 0
            queue.QueueThread(() => { });

            var settings = WithStallWindow(50);
            var check = new SigningHealthCheck(settings, NSubstitute.Substitute.For<ILogger>(), queue);

            // Wait past the stall window while the worker is blocked and jobs remain queued.
            await Task.Delay(250);

            var result = await check.CheckHealthAsync(Context());
            gate.Set(); // release the worker so the queue drains and its thread exits

            Assert.Multiple(() =>
            {
                Assert.That(result.Status, Is.EqualTo(HealthStatus.Unhealthy));
                Assert.That(result.Description, Does.Contain("not draining"));
            });
        }

        // Points signtool at a certificate file that does not exist so signing fails the
        // same way a missing private key would ("No private key is available.").
        private static Settings BrokenCertSettings()
        {
            var good = OneTimeUnitTestSetup.SignToolSettings!;
            return new Settings
            {
                SignToolPath = good.SignToolPath,
                SignToolOptions = "sign /fd SHA256 /f \"{BaseDirectory}does-not-exist.pfx\" /p \"password\" /v \"{FilePath}\"",
                SigntoolTimeoutInMs = good.SigntoolTimeoutInMs,
                MaxRequestBodySize = good.MaxRequestBodySize,
                SemaphoreSlimProcessPerCpuLimit = good.SemaphoreSlimProcessPerCpuLimit,
                HealthCheckCacheInMs = good.HealthCheckCacheInMs,
                HealthCheckQueueStallInMs = good.HealthCheckQueueStallInMs,
                OpenSSL = good.OpenSSL
            };
        }

        [Test]
        public async Task Ready_IsUnhealthy_WhenPrivateKeyIsMissing()
        {
            var check = new SigningHealthCheck(BrokenCertSettings(), NSubstitute.Substitute.For<ILogger>());

            await check.RefreshAsync();
            var result = await check.CheckHealthAsync(Context());

            Assert.Multiple(() =>
            {
                Assert.That(result.Status, Is.EqualTo(HealthStatus.Unhealthy));
                Assert.That(result.Description, Does.Contain("Code signing is failing"));
            });
        }
    }
}
