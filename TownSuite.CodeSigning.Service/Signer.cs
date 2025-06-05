using Microsoft.VisualBasic;
using System.Diagnostics;
using System.Text;
using System.Threading;

namespace TownSuite.CodeSigning.Service
{
    public class Signer : IDisposable
    {
        readonly Settings _settings;
        StringBuilder msg = new StringBuilder();
        Process p;
        readonly ILogger _logger;
        public Signer(Settings settings, ILogger logger)
        {
            _settings = settings;
            _logger = logger;
        }

        private CancellationToken _cancellationToken => new CancellationTokenSource(_settings.SigntoolTimeoutInMs).Token;
        public void Dispose()
        {
            if (p == null)
            {
                return;
            }
            p.OutputDataReceived -= process_OutputDataReceived;
            p.ErrorDataReceived -= process_ErrorDataReceived;
            p.Dispose();
        }

        public async Task<(bool IsSigned, string Message)> SignAsync(string currentfile, bool isDetached)
        {
            p = new System.Diagnostics.Process();
            p.StartInfo.FileName = _settings.SignToolPath;

            p.StartInfo.Arguments = isDetached ? _settings.SignToolDetachedOptions.Replace("{FilePath}", currentfile) :   _settings.SignToolOptions.Replace("{FilePath}", currentfile);
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


            await p.WaitForExitAsync(_cancellationToken);
            if (_cancellationToken.IsCancellationRequested)
            {
                msg.AppendLine("signtool timeout reached. Cancelling code signing attempt.");
                _logger.LogWarning(msg.ToString());
                try
                {
                    p.Kill();
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
