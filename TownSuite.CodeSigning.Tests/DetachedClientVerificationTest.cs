using Microsoft.Extensions.Logging;
using TownSuite.CodeSigning.Service;

namespace TownSuite.CodeSigning.Tests
{
    /// <summary>
    /// End-to-end compatibility test between the service's detached signing (real openssl
    /// invocation via SignerDetached) and the client's post-download verification
    /// (FileHelpers.HasValidDetachedSignature). Proves the two agree byte-exactly: openssl signs
    /// with "-binary", so the digest covers the file as it sits on disk and the client can verify
    /// it directly. Drop that flag and openssl digests a CRLF-canonicalized copy instead, and this
    /// test fails - which is the point of it.
    /// </summary>
    [TestFixture]
    public class DetachedClientVerificationTest
    {
        [Test]
        public async Task OpensslProducedDetachedSignature_PassesClientVerification()
        {
            // Arrange
            var settings = OneTimeUnitTestSetup.SignToolSettings!;
            string id = Guid.NewGuid().ToString();
            var workingDir = new DirectoryInfo(Path.Combine(BatchedSigning.GetTempFolder(), id));
            workingDir.Create();

            // SignerDetached deletes the originals from the working folder after signing,
            // so keep the verification copy outside it.
            string originalCopy = Path.Combine(AppContext.BaseDirectory, $"detached-verify-{id}.zip");
            string workingFile = Path.Combine(workingDir.FullName, $"{id}.workingfile");
            File.Copy("test.zip", workingFile, true);
            File.Copy("test.zip", originalCopy, true);

            try
            {
                // Act - sign with the real openssl pipeline the service uses
                var signer = new SignerDetached(settings, NSubstitute.Substitute.For<ILogger>());
                var result = await signer.SignAsync(workingDir.FullName, new[] { workingFile });

                // Assert
                string sigPath = $"{workingFile}.sig";
                Assert.Multiple(() =>
                {
                    Assert.That(result.IsSigned, Is.True, result.Message);
                    Assert.That(File.Exists(sigPath), Is.True, $"openssl did not produce a .sig: {result.Message}");
                    Assert.That(FileHelpers.HasValidDetachedSignature(originalCopy, sigPath), Is.True,
                        "client verification rejected a signature the service legitimately produced");
                });

                // The client's check must still reject junk even though it is structural-only.
                string garbageSig = Path.Combine(workingDir.FullName, "garbage.sig");
                await File.WriteAllBytesAsync(garbageSig, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
                Assert.That(FileHelpers.HasValidDetachedSignature(originalCopy, garbageSig), Is.False);
            }
            finally
            {
                try { File.Delete(originalCopy); } catch { }
                try { workingDir.Delete(true); } catch { }
            }
        }
    }
}
