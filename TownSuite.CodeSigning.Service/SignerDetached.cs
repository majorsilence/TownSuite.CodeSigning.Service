using Microsoft.VisualBasic;
using System.Diagnostics;
using System.Security;
using System.Text;
using System.Threading;

namespace TownSuite.CodeSigning.Service
{
    public class SignerDetached : ISigner
    {
        readonly Settings _settings;
        readonly StringBuilder msg = new StringBuilder();

        // openssl's stdout and stderr are drained on two separate threadpool threads, so every
        // touch of msg has to be synchronized. StringBuilder is not thread-safe: concurrent
        // appends corrupt its internal chunk list and throw "Destination is too short" out of
        // AsyncStreamReader, which rethrows on a threadpool thread and takes the process down.
        readonly object _msgLock = new object();

        readonly ILogger _logger;
        public SignerDetached(Settings settings, ILogger logger)
        {
            _settings = settings;
            _logger = logger;
        }

        private void AppendMessage(string line)
        {
            lock (_msgLock)
            {
                msg.AppendLine(line);
            }
        }

        private string MessageSnapshot()
        {
            lock (_msgLock)
            {
                return msg.ToString();
            }
        }

        private void KillProcess(System.Diagnostics.Process p, string toolName)
        {
            try
            {
                p.Kill(entireProcessTree: true);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, $"{toolName} process exit failure");
            }
        }

        public async Task<(bool IsSigned, string Message)> SignAsync(string workingDir, string[] files)
        {
            using var timeout = new CancellationTokenSource(_settings.SigntoolTimeoutInMs * files.Length);

            foreach (var file in files)
            {
                using var p = new System.Diagnostics.Process();
                p.StartInfo.FileName = _settings.OpenSSL.OpenSslPath;

                string arguments = _settings.OpenSSL.OpenSslOptions
                    .Replace("{FilePath}", file)
                    .Replace("{BaseDirectory}", AppContext.BaseDirectory + System.IO.Path.DirectorySeparatorChar);

                if (arguments.Contains("{WorkingDirectory}"))
                {
                    arguments = arguments.Replace("{WorkingDirectory}", workingDir + System.IO.Path.DirectorySeparatorChar);
                }

                p.StartInfo.Arguments = arguments;

                p.StartInfo.WorkingDirectory = workingDir;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.ErrorDialog = false;
                p.StartInfo.CreateNoWindow = true;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.RedirectStandardOutput = true;

                p.Start();

                p.ErrorDataReceived += process_ErrorDataReceived;
                p.OutputDataReceived += process_OutputDataReceived;

                p.BeginErrorReadLine();
                p.BeginOutputReadLine();

                try
                {
                    await p.WaitForExitAsync(timeout.Token);
                }
                catch (OperationCanceledException) when (timeout.IsCancellationRequested)
                {
                    // WaitForExitAsync throws on cancellation, so the kill has to happen here.
                    // Without it a wedged openssl is left running and its handles leak.
                    AppendMessage("openssl timeout reached. Cancelling code signing attempt.");
                    _logger.LogWarning(MessageSnapshot());
                    KillProcess(p, "openssl");

                    return (false, MessageSnapshot());
                }

                // TODO: determine if openssl was successful based on exit code and/or output, and return false if it was not successful.
                // For now we will return true regardless of the exit code, as long as the process completed within the timeout,
                // and log the exit code and output for debugging purposes.
                _logger.LogInformation($"OpensslInternal ExitCode: {p.ExitCode}, Message: {MessageSnapshot()}");
            }

            await TimeStamp(workingDir, files, timeout);

            CleanupOriginalFiles(workingDir, files);
            return (true, MessageSnapshot());
        }

        private async Task TimeStamp(string workingDir, string[] files, CancellationTokenSource timeout)
        {
            if (string.IsNullOrWhiteSpace(_settings.OpenSSL.OsslSignCodePath) || string.IsNullOrWhiteSpace(_settings.OpenSSL.TimestampOptions))
            {
                return;
            }
            foreach (var file in files)
            {
                using var p = new System.Diagnostics.Process();
                p.StartInfo.FileName = _settings.OpenSSL.OsslSignCodePath;

                string arguments = _settings.OpenSSL.TimestampOptions
                    .Replace("{FilePath}", file);

                p.StartInfo.Arguments = arguments;

                p.StartInfo.WorkingDirectory = workingDir;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.ErrorDialog = false;
                p.StartInfo.CreateNoWindow = true;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.RedirectStandardOutput = true;

                p.Start();

                p.ErrorDataReceived += process_ErrorDataReceived;
                p.OutputDataReceived += process_OutputDataReceived;

                p.BeginErrorReadLine();
                p.BeginOutputReadLine();

                try
                {
                    await p.WaitForExitAsync(timeout.Token);
                }
                catch (OperationCanceledException) when (timeout.IsCancellationRequested)
                {
                    // WaitForExitAsync throws on cancellation, so the kill has to happen here.
                    // Without it a wedged osslsigncode is left running and its handles leak.
                    AppendMessage("Opensslsigntool timeout reached. Cancelling code signing attempt.");
                    _logger.LogWarning(MessageSnapshot());
                    KillProcess(p, "Opensslsigntool");

                    // The timeout budget is shared across every file, so once it fires there is no
                    // point starting the next one: its WaitForExitAsync would fail immediately.
                    // Returning here also avoids reading p.ExitCode on a process that may not have
                    // exited, which throws InvalidOperationException.
                    return;
                }

                _logger.LogInformation($"Opensslsigntool Internal ExitCode: {p.ExitCode}, Message: {MessageSnapshot()}");
            }
        }

        private void CleanupOriginalFiles(string workingDir, string[] files)
        {
            foreach (var file in files)
            {
                try
                {
                    System.IO.File.Delete(System.IO.Path.Combine(workingDir, file));
                }
                catch
                {
                    _logger.LogInformation($"failed to cleanup {file}.  Will try again later");
                }
            }

            // delete any non .sig, .error, .signed files in the working directory, as these are likely the original files that were signed, and we want to clean them up to save space.
            var dirInfo = new System.IO.DirectoryInfo(workingDir);
            var filesToDelete = dirInfo.GetFiles().Where(f => !f.Extension.Equals(".sig", StringComparison.OrdinalIgnoreCase)
                && !f.Extension.Equals(".error", StringComparison.OrdinalIgnoreCase)
                && !f.Extension.Equals(".signed", StringComparison.OrdinalIgnoreCase));

            foreach (var file in filesToDelete)
            {
                try
                {
                    file.Delete();
                }
                catch
                {
                    _logger.LogInformation($"failed to cleanup {file.FullName}.  Will try again later");
                }
            }
        }

        public string GetFileName(string id)
        {
            if (string.IsNullOrWhiteSpace(_settings.OpenSSL.OsslSignCodePath) || string.IsNullOrWhiteSpace(_settings.OpenSSL.TimestampOptions))
            {
                return $"{id}.workingfile.sig";
            }

            return $"{id}.workingfile.timestamped.sig";
        }

        private void process_ErrorDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
            {
                AppendMessage($"OpensslInternal StandardError: {e.Data}");
            }
        }

        private void process_OutputDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
            {
                AppendMessage($"OpensslInternal StandardOutput: {e.Data}");
            }
        }

    }
}
