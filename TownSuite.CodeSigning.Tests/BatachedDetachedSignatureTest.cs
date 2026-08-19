using Microsoft.Extensions.Logging;
using TownSuite.CodeSigning.Service;

namespace TownSuite.CodeSigning.Tests
{
    [TestFixture]
    public class BatachedDetachedSignatureTest
    {

        public static object[] TestFiles =
        {
            new string[]{"srcfile1.zip"},
            new string[]{ "srcfile2.zip", "srcfile3.zip" }
        };

        [Test, TestCaseSource(nameof(TestFiles))]
        public async Task Test1(string[] srcFiles)
        {
            // Arrange
            var srcAssemblyPath = Path.Combine(AppContext.BaseDirectory, "test.zip");


            var ids = new List<string>();
            var results = new List<Microsoft.AspNetCore.Http.HttpResults.Ok<string>>();
            var settings = OneTimeUnitTestSetup.SignToolSettings;

            foreach (var filepath in srcFiles)
            {
                File.Copy("test.zip", Path.Combine(AppContext.BaseDirectory, filepath), true);
                using var fs = new FileStream(srcAssemblyPath, FileMode.Open, FileAccess.Read);
                var signer = new SignerDetached(settings, NSubstitute.Substitute.For<ILogger<SignerDetached>>());
                var ur = await BatchedSigning.Sign(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>(), fs, NSubstitute.Substitute.For<ILogger>(), signer);
                var uploadResult = ur as Microsoft.AspNetCore.Http.HttpResults.Ok<string>;
                results.Add(uploadResult);
                string id = uploadResult?.Value?.Replace("\"", "");
                ids.Add(id);
            }


            // Assert

            Assert.Multiple(() =>
            {
                foreach (var uploadResult in results)
                {
                    Assert.That(uploadResult, Is.Not.Null);
                    Assert.That(uploadResult.StatusCode, Is.EqualTo(200));
                }
            });

            // Act download


            bool doLoop = true;
            int count = 0;
            while (doLoop && count <20)
            {
                for (int i=0;i<ids.Count;i++)
                {
                    var signer = new SignerDetached(settings, NSubstitute.Substitute.For<ILogger<SignerDetached>>());
                    string id = ids[i];
                    string signaturePath = Path.Combine(AppContext.BaseDirectory, signer.GetFileName(id));
                    var dr = await BatchedSigning.Get(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>(), id, signer);

                    if (dr is Microsoft.AspNetCore.Http.HttpResults.FileStreamHttpResult streamResult)
                    {
                        doLoop = false;
                        await using var resultStream = streamResult.FileStream;
                        await using var file = File.OpenWrite(signaturePath);
                        await resultStream.CopyToAsync(file);
                    }
                    else if (dr is Microsoft.AspNetCore.Http.HttpResults.FileContentHttpResult file)
                    {
                        doLoop = false;
                        await File.WriteAllBytesAsync(signaturePath, file.FileContents.ToArray());
                    }
                    else if (dr is Microsoft.AspNetCore.Http.HttpResults.ProblemHttpResult phr)
                    {
                        if (phr.StatusCode == 425)
                        {
                            await Task.Delay(1000);
                        }
                        else
                        {
                            doLoop = false;
                            Assert.Fail();
                        }
                    }

                    count++;
                }
            }

            for (int i = 0; i < ids.Count; i++)
            {
                var id = ids[i];
                var originalFile = Path.Combine(AppContext.BaseDirectory, srcFiles[i]);
                var signer = new SignerDetached(settings, NSubstitute.Substitute.For<ILogger<SignerDetached>>());
                var signatureFile = Path.Combine(AppContext.BaseDirectory, signer.GetFileName(id));

                // Byte-exact check: the digest must cover the file as it sits on disk. This is the
                // regression guard for the "-binary" flag in OpenSslOptions - drop it and openssl
                // silently digests a CRLF-canonicalized copy of the content instead, producing a
                // .sig that does not match the bytes we ship. There is deliberately no fallback
                // assertion here; a "the file exists and is non-empty" escape hatch hides exactly
                // the defect this test exists to catch.
                var valid = Certs.ValidateDetachedSignature(originalFile, signatureFile, OneTimeUnitTestSetup.certPath, OneTimeUnitTestSetup.password);
                Assert.IsTrue(valid,
                    $"detached signature does not verify against the original bytes of {originalFile}");

                File.Delete(signatureFile);
            }

        }

        // Reproduction of the TownSuite.Chat manifest bug: a manifest generated on a linux agent
        // uses LF, and openssl without "-binary" digests a CRLF-rewritten copy of it, so the .sig
        // covers different bytes than the file that gets uploaded. Windows agents happened to write
        // CRLF already, which made the rewrite a no-op and hid the defect. Both line endings must
        // verify byte-exactly.
        [TestCase("lf")]
        [TestCase("crlf")]
        public async Task DetachedSignature_CoversRawBytes_RegardlessOfLineEndings(string lineEnding)
        {
            string eol = lineEnding == "lf" ? "\n" : "\r\n";
            string content = $"manifest-line-one{eol}manifest-line-two{eol}";

            var settings = OneTimeUnitTestSetup.SignToolSettings!;
            string id = Guid.NewGuid().ToString();
            var workingDir = new DirectoryInfo(Path.Combine(BatchedSigning.GetTempFolder(), id));
            workingDir.Create();

            // SignerDetached deletes the originals from the working folder once it is done, so the
            // copy used for verification has to live outside it.
            string originalCopy = Path.Combine(AppContext.BaseDirectory, $"manifest-{lineEnding}-{id}.txt");
            string workingFile = Path.Combine(workingDir.FullName, $"{id}.workingfile");

            // WriteAllText would rewrite the line endings on the way out, which is the exact
            // transform under test - write the bytes verbatim instead.
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(content);
            await File.WriteAllBytesAsync(workingFile, bytes);
            await File.WriteAllBytesAsync(originalCopy, bytes);

            try
            {
                var signer = new SignerDetached(settings, NSubstitute.Substitute.For<ILogger<SignerDetached>>());
                var result = await signer.SignAsync(workingDir.FullName, new[] { workingFile });

                string sigPath = $"{workingFile}.sig";
                Assert.That(File.Exists(sigPath), Is.True, $"openssl did not produce a .sig: {result.Message}");
                Assert.That(
                    Certs.ValidateDetachedSignature(originalCopy, sigPath, OneTimeUnitTestSetup.certPath, OneTimeUnitTestSetup.password),
                    Is.True,
                    $"{lineEnding} content: signature does not verify against the original bytes");
            }
            finally
            {
                try { File.Delete(originalCopy); } catch { }
                try { workingDir.Delete(true); } catch { }
            }
        }
    }
}
