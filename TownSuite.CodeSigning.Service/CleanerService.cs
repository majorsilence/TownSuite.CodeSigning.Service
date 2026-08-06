
using System.Runtime;
using System.Threading;

namespace TownSuite.CodeSigning.Service
{
    public class CleanerService : BackgroundService
    {
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                CleanupOldFolders();
                await Task.Delay(TimeSpan.FromMinutes(10));
            }
        }

        static void CleanupOldFolders()
        {
            // if a working folder is more than 1 hour old delete it
            var baseFolder = new DirectoryInfo(BatchedSigning.GetTempFolder());
            var folders = baseFolder.GetDirectories();
            DateTime currentTime = DateTime.Now;
            foreach (var folder in folders)
            {
                // The readiness canary's folder is long lived and reused by every run, so it is
                // always older than the cutoff. Deleting it races with an in-flight canary and
                // logged a delete failure every pass. Sweep stale files out of it instead, so a
                // canary that failed to clean up after itself cannot accumulate forever.
                if (string.Equals(folder.Name, SigningHealthCheck.CanaryFolderName,
                        StringComparison.OrdinalIgnoreCase))
                {
                    CleanupOldFiles(folder, currentTime);
                    continue;
                }

                TimeSpan age = currentTime - folder.CreationTime;
                if (age.TotalHours > 1)
                {
                    try
                    {
                        folder.Delete(true);
                    }
                    catch (Exception)
                    {
                        Console.Error.WriteLine($"Failed to delete folder {folder.FullName} and will try again later");
                    }

                }
            }

        }

        // Deletes files more than 1 hour old while leaving the folder itself in place.
        static void CleanupOldFiles(DirectoryInfo folder, DateTime currentTime)
        {
            foreach (var file in folder.GetFiles())
            {
                if ((currentTime - file.CreationTime).TotalHours <= 1)
                {
                    continue;
                }

                try
                {
                    file.Delete();
                }
                catch (Exception)
                {
                    Console.Error.WriteLine($"Failed to delete file {file.FullName} and will try again later");
                }
            }
        }
    }
}
