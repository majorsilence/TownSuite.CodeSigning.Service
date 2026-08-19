using Microsoft.Extensions.Logging;
using TownSuite.CodeSigning.Service;

namespace TownSuite.CodeSigning.Tests
{
    [SetUpFixture]
    public class OneTimeUnitTestSetup
    {
        public const string certPath = "testcert.pfx";
        public const string password = "password";
        // Download signtool as part of the windows sdk https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/

        // If you have it installed, set the path to signtool.exe as an environment variable
        // or add to your path variable. If not, the tests will attempt to find it in the current directory and then fail if it is not found.
        // signtool can often can be found in a folder such as C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64
        static readonly string SignToolPath = System.Environment.GetEnvironmentVariable("SIGNTOOL_PATH")
            ?? "signtool.exe";
        public static Settings? SignToolSettings { get; private set; }

        [OneTimeSetUp]
        public void Setup()
        {
            Certs.CreateTestCert(certPath, password);
            Certs.ConvertPfxToPrivatePublicPem(certPath, password, out string privateKeyPem, out string publicCertPem);
            System.IO.File.WriteAllText("testcert.key", privateKeyPem);
            System.IO.File.WriteAllText("testcert.crt", publicCertPem);


            SignToolSettings = new Settings()
            {
                MaxRequestBodySize = 1000000,
                SignToolOptions = "sign /fd SHA256 /f \"{BaseDirectory}testcert.pfx\" /p \"password\" /t \"http://timestamp.digicert.com\" /v \"{FilePath}\"",
                SignToolPath = SignToolPath,
                SigntoolTimeoutInMs = 10000,
                SemaphoreSlimProcessPerCpuLimit=1,
                OpenSSL = new OpenSSLSettings()
                {
                    OpenSslPath = Environment.GetEnvironmentVariable("OPENSSL_PATH") ?? "openssl",
                    OpenSslOptions = "cms -sign -in \"{FilePath}\" -signer \"{BaseDirectory}testcert.crt\" -inkey \"{BaseDirectory}testcert.key\" -keyform P12 -passin pass:password -outform DER -out \"{FilePath}.sig\" -md sha256 -binary",
                    OpenSslTimeoutInMs = 30000,
                    OsslSignCodePath = "osslsigncode",
                    TimestampOptions = "add -t \"http://timestamp.digicert.com\" -in \"{FilePath}.sig\" -out \"{FilePath}.timestamped.sig\""
                }
            };

            CodeSigning.Service.Queuing.SetSemaphore(SignToolSettings);
        }


        [OneTimeTearDown]
        public void Teardown()
        {
            System.IO.File.Delete(certPath);
        }
    }
}