using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TownSuite.CodeSigning.Client
{
    internal class SigningClientDetached : SigningClient
    {
        private readonly HttpClient _client;
        private readonly string _url;
        private readonly DetachedSignatureArgs _signToolSettings;
        public SigningClientDetached(HttpClient client, string baseUrl,
            DetachedSignatureArgs _signToolSettings) : base(client, baseUrl)
        {
            _client = client;
            _client.DefaultRequestHeaders.Add("X-DETACHED-SIGNING", "indeed");
            _url = baseUrl;
            this._signToolSettings = _signToolSettings;
        }

        private List<(string Id, string FilePath)> TrackedFiles = new();


        public override async Task<(string FailedFile, string Message)[]> UploadFiles(bool quickFail, bool ignoreFailures,
            string[] filepaths)
        {     
            var hashFiles = GenerateHashesInParallel(filepaths.ToList());
            return await base.UploadFiles(quickFail, ignoreFailures, hashFiles.ToArray());
        }

        public override async Task<(string FailedFile, string Message)[]> DownloadSignedFiles(bool quickFail, bool ignoreFailures,
            int batchTimeoutInSeconds)
        {
            var startTime = DateTime.UtcNow;
            var failedUploads = new List<(string FailedFile, string Message)>();

            int count = 0;
            while ((DateTime.UtcNow - startTime).TotalSeconds < batchTimeoutInSeconds
                && TrackedFiles.Any())
            {
                var results = await DownloadSignedFiles_Internal(quickFail, ignoreFailures, count % 60 == 0);
                failedUploads.AddRange(results.Failures);

                // Remove successfully processed files from TrackedFiles
                var tasks = new List<Task>();
                foreach (var file in results.GoodFiles)
                {
                    // apply the signed hash to the original file
                    string hashFilePath = $"{file.FilePath}.hash";
                    if (File.Exists(hashFilePath))
                    {
                        tasks.Add(SignAsync(file.FilePath, hashFilePath, CancellationToken.None));
                    }
                    else
                    {
                        Console.WriteLine($"Hash file not found for {file.FilePath}, skipping.");
                    }

                    TrackedFiles.Remove(file);
                }
                foreach (var file in results.Failures)
                {
                    TrackedFiles.RemoveAll(x => x.FilePath == file.FailedFile);
                }
                await Task.WhenAll(tasks);
                
                await Task.Delay(1000);
                count++;
            }

            return failedUploads.ToArray();
        }

        static List<string> GenerateHashesInParallel(List<string> filePaths)
        {
            var fileHashPaths = new List<string>();
            var lockObject = new object();

            Parallel.ForEach(filePaths, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, filePath =>
            {
                byte[] hashValue;
                using (FileStream fileStream = File.OpenRead(filePath))
                {
                    using (SHA256 sha256 = SHA256.Create())
                    {
                        hashValue = sha256.ComputeHash(fileStream);
                    }
                }

                string hashFilePath = $"{filePath}.hash";
                lock (lockObject)
                {
                    fileHashPaths.Add(hashFilePath);
                }
              
                File.WriteAllBytes(hashFilePath, hashValue);
                Console.WriteLine($"Hash generated and saved to {hashFilePath}");
            });

            return fileHashPaths;
        }

        public async Task<bool> SignAsync(string currentfile, string hashFile, CancellationToken cancellationToken)
        {
            using var p = new System.Diagnostics.Process();
            p.StartInfo.FileName = _signToolSettings.SigntoolPath;

            p.StartInfo.Arguments = _signToolSettings.SigntoolDetachedArgs.Replace("{AssemblyFilePath}", currentfile).Replace("{HashFilePath}", hashFile);
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.ErrorDialog = false;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.RedirectStandardOutput = true;

            p.Start();

            // see https://stackoverflow.com/questions/5693191/c-sharp-run-multiple-non-blocking-external-programs-in-parallel/5695109#5695109
            p.ErrorDataReceived += process_ErrorDataReceived;
            p.OutputDataReceived += process_OutputDataReceived;

            p.BeginErrorReadLine();
            p.BeginOutputReadLine();


            await p.WaitForExitAsync(cancellationToken);
            if (cancellationToken.IsCancellationRequested)
            {
                Console.WriteLine("signtool timeout reached. Cancelling code signing attempt.");
                try
                {
                    p.Kill();
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"signtool process exit failure {ex}");
                }

            }

            Console.WriteLine($"SignToolInternal ExitCode: {p.ExitCode}");

            System.IO.File.Delete(hashFile); // Clean up the hash file after signing
            return p.ExitCode == 0;
        }

        private void process_ErrorDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
            {
                Console.Error.WriteLine($"SignToolInternal StandardError: {e.Data}");
            }
        }

        private void process_OutputDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
            {
                Console.WriteLine($"SignToolInternal StandardOutput: {e.Data}");
            }
        }
    }

}
