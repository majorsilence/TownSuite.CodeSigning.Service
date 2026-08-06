using Microsoft.VisualBasic;
using System.Diagnostics;
using System.Text;
using System.Threading;

namespace TownSuite.CodeSigning.Service
{
    public class Signer : ISigner
    {
        readonly Settings _settings;
        StringBuilder msg = new StringBuilder();

        readonly ILogger _logger;
        public Signer(Settings settings, ILogger logger)
        {
            _settings = settings;
            _logger = logger;
        }

        public async Task<(bool IsSigned, string Message)> SignAsync(string workingDir, string[] files)
        {
            using var timeout = new CancellationTokenSource(_settings.SigntoolTimeoutInMs * files.Length);

            using var p = new System.Diagnostics.Process();
            p.StartInfo.FileName = _settings.SignToolPath;

            if (files.Length == 1)
            {
                p.StartInfo.Arguments = _settings.SignToolOptions
                    .Replace("{FilePath}", files[0])
                    .Replace("{BaseDirectory}", AppContext.BaseDirectory + System.IO.Path.DirectorySeparatorChar);
            }
            else
            {
                p.StartInfo.Arguments = _settings.SignToolOptions
                    .Replace("\"{FilePath}\"", string.Join(" ", files))
                    .Replace("{BaseDirectory}", AppContext.BaseDirectory + System.IO.Path.DirectorySeparatorChar);
            }

            p.StartInfo.WorkingDirectory = workingDir;
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


            try
            {
                await p.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested)
            {
                // WaitForExitAsync throws on cancellation, so the kill has to happen here.
                // Without it a wedged signtool is left running and its handles leak.
                msg.AppendLine("signtool timeout reached. Cancelling code signing attempt.");
                _logger.LogWarning(msg.ToString());
                try
                {
                    p.Kill(entireProcessTree: true);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "signtool process exit failure");
                }

                return (false, msg.ToString());
            }

            _logger.LogInformation($"SignToolInternal ExitCode: {p.ExitCode}, Message: {msg.ToString()}");

            return (p.ExitCode == 0, msg.ToString());
        }

        public string GetFileName(string id)
        {
            return $"{id}.workingfile";
        }

        private void process_ErrorDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
            {
                msg.AppendLine($"SignToolInternal StandardError: {e.Data}");
            }
        }

        private void process_OutputDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
            {
                msg.AppendLine($"SignToolInternal StandardOutput: {e.Data}");
            }
        }

    }
}
