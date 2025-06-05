using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace TownSuite.CodeSigning.Client
{
    internal class SigningClient
    {
        private readonly HttpClient _client;
        private readonly string _url;
        public SigningClient(HttpClient client, string baseUrl)
        {
            _client = client;
            _url = baseUrl;
        }

        private List<(string Id, string FilePath)> TrackedFiles = new();


        public virtual async Task<(string FailedFile, string Message)[]> UploadFiles(bool quickFail, bool ignoreFailures,
            string[] filepaths)
        {
            var failedUploads = new List<(string FailedFile, string Message)>();

            var urk = new Uri(_url);
            string url = $"{urk.Scheme}://{urk.Host}:{urk.Port}/sign/batch";
            foreach (string filepath in filepaths)
            {
                try
                {
                    var isHealthy = await HealthCheck();
                    if (!isHealthy)
                    {
                        failedUploads.Add((filepath, "health check failed"));
                        continue;
                    }

                    var request = new HttpRequestMessage(HttpMethod.Post, url);
                    await using var fs = File.OpenRead(filepath);
                    request.Content = new StreamContent(fs);
                    Console.WriteLine($"Uploading file: {filepath}");
                    var response = await _client.SendAsync(request);
                    fs.Close();
                    if (response.IsSuccessStatusCode)
                    {
                        string id = await response.Content.ReadAsStringAsync();
                        TrackedFiles.Add((id.Replace("\"", ""), filepath));
                    }
                    else
                    {
                        var failedOutput = await response.Content.ReadAsStringAsync();
                        failedUploads.Add((filepath, failedOutput));

                        if (quickFail && !ignoreFailures)
                        {
                            Console.WriteLine("Quick fail");
                            Console.WriteLine($"Failed to sign file: {filepath}");
                            Console.WriteLine(failedOutput);
                            Environment.Exit(-1);
                        }
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine($"Failed to sign file: {filepath}");
                    throw;
                }

            }
            return failedUploads.ToArray();
        }

        public virtual async Task<(string FailedFile, string Message)[]> DownloadSignedFiles(bool quickFail, bool ignoreFailures,
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
                foreach (var file in results.GoodFiles)
                {
                    TrackedFiles.Remove(file);
                }
                foreach (var file in results.Failures)
                {
                    TrackedFiles.RemoveAll(x => x.FilePath == file.FailedFile);
                }
                await Task.Delay(1000);
                count++;
            }

            return failedUploads.ToArray();
        }

        public async Task<((string FailedFile, string Message)[] Failures, (string Id, string FilePath)[] GoodFiles)>
            DownloadSignedFiles_Internal(bool quickFail, bool ignoreFailures, bool showPollingMessage)
        {
            var urk = new Uri(_url);
            string url = $"{urk.Scheme}://{urk.Host}:{urk.Port}/sign/batch";
            var goodFiles = new List<(string Id, string FilePath)>();
            var failedUploads = new List<(string FailedFile, string Message)>();

            foreach (var file in TrackedFiles)
            {
                string pollUrl = $"{url}?id={file.Id}";
                if (showPollingMessage)
                {
                    Console.WriteLine($"Polling download for file {file.FilePath}");
                }

                var response = await _client.GetAsync(pollUrl);
                if (response.IsSuccessStatusCode)
                {
                    await using var resultStream = await response.Content.ReadAsStreamAsync();
                    await using var fileStream = File.OpenWrite(file.FilePath);
                    await resultStream.CopyToAsync(fileStream);
                    goodFiles.Add(file);
                    Console.WriteLine($"Signed file: {file.FilePath}");
                }
                else if ((int)response.StatusCode == 425)
                {
                    // not yet processed
                    continue;
                }
                else
                {
                    var failedOutput = await response.Content.ReadAsStringAsync();
                    failedUploads.Add((file.FilePath, failedOutput));

                    if (quickFail && !ignoreFailures)
                    {
                        Console.WriteLine("Quick fail");
                        Console.WriteLine($"Failed to sign file: {file.FilePath}");
                        Console.WriteLine(failedOutput);
                        Environment.Exit(-1);
                    }
                }
            }

            return (failedUploads.ToArray(), goodFiles.ToArray());
        }

        public async Task<bool> HealthCheck()
        {
            try
            {
                var urk = new Uri(_url);
                string healthCheckUrl = $"{urk.Scheme}://{urk.Host}:{urk.Port}/healthz";

                var response = await _client.GetAsync(healthCheckUrl);
                if (response.IsSuccessStatusCode)
                {
                    return true;
                }
                else
                {
                    Console.WriteLine("Health check failed");
                    var failedOutput = await response.Content.ReadAsStringAsync();
                    Console.WriteLine(failedOutput);
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Health check failed" + ex.Message);
                return false;
            }

        }
    }
}
