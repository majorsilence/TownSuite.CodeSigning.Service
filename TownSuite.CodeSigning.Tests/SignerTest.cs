using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TownSuite.CodeSigning.Service;

namespace TownSuite.CodeSigning.Tests
{
    [TestFixture]
    public class SignerTest
    {
        [Test]
        public async Task Test1()
        {
            // Arrange
            var srcAssemblyPath = "test.dll";
            var assemblyPath = System.IO.Path.Combine(AppContext.BaseDirectory, "test_signed.dll");
            var settings = OneTimeUnitTestSetup.SignToolSettings;

            var signer = new Signer(settings, NSubstitute.Substitute.For<ILogger>());
            // Act
            System.IO.File.Copy(srcAssemblyPath, assemblyPath, true);
            var result = await signer.SignAsync(AppContext.BaseDirectory, [assemblyPath]);
            // Assert

            Assert.Multiple(() =>
            {
                Assert.That(result.IsSigned, Is.EqualTo(true), result.Message);
                Assert.IsTrue(Certs.ValidateDigitalSignature(assemblyPath, OneTimeUnitTestSetup.certPath, OneTimeUnitTestSetup.password));
            });
        }

        private const int ChattyLineCount = 400;

        // Emits ChattyLineCount lines on stdout interleaved with the same number on stderr, so the
        // two AsyncStreamReader threads append concurrently for the whole run.
        private static Settings ChattyProcessSettings()
        {
            var good = OneTimeUnitTestSetup.SignToolSettings!;
            return new Settings
            {
                SignToolPath = "cmd.exe",
                SignToolOptions =
                    $"/c for /L %i in (1,1,{ChattyLineCount}) do @(echo out-%i& echo err-%i 1>&2)",
                SigntoolTimeoutInMs = 60000,
                MaxRequestBodySize = good.MaxRequestBodySize,
                SemaphoreSlimProcessPerCpuLimit = good.SemaphoreSlimProcessPerCpuLimit,
                HealthCheckCacheInMs = good.HealthCheckCacheInMs,
                HealthCheckQueueStallInMs = good.HealthCheckQueueStallInMs,
                OpenSSL = good.OpenSSL
            };
        }

        [Test]
        [Platform("Win")]
        public async Task InterleavedStdoutAndStderr_IsCapturedWithoutCorruption()
        {
            // Regression: msg was a plain StringBuilder appended from both the stdout and stderr
            // reader threads. StringBuilder is not thread-safe, so concurrent appends corrupted its
            // chunk list and threw "Destination is too short. (Parameter 'destination')" out of
            // AsyncStreamReader.FlushMessageQueue -- rethrown on a threadpool thread, killing the
            // whole service process rather than failing the one signing request.
            var settings = ChattyProcessSettings();

            var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(async _ =>
            {
                var signer = new Signer(settings, NSubstitute.Substitute.For<ILogger>());
                return await signer.SignAsync(AppContext.BaseDirectory, new[] { "unused" });
            }));

            Assert.Multiple(() =>
            {
                foreach (var result in results)
                {
                    var lines = result.Message
                        .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                        .Select(l => l.TrimEnd('\r'))
                        .ToList();

                    // Every line must be intact. A corrupted builder splices lines together or
                    // drops them, so anything not starting with a known prefix is torn output.
                    var torn = lines.Where(l =>
                        !l.StartsWith("SignToolInternal StandardOutput: ", StringComparison.Ordinal) &&
                        !l.StartsWith("SignToolInternal StandardError: ", StringComparison.Ordinal))
                        .ToList();

                    Assert.That(torn, Is.Empty, $"torn output lines: {string.Join(" | ", torn.Take(5))}");

                    Assert.That(lines.Count(l => l.StartsWith("SignToolInternal StandardOutput: ", StringComparison.Ordinal)),
                        Is.EqualTo(ChattyLineCount), "stdout lines lost");
                    Assert.That(lines.Count(l => l.StartsWith("SignToolInternal StandardError: ", StringComparison.Ordinal)),
                        Is.EqualTo(ChattyLineCount), "stderr lines lost");
                }
            });
        }
    }
}
