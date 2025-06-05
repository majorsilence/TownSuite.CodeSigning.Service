using Microsoft.Extensions.Logging;
using System.Runtime.InteropServices;

namespace TownSuite.CodeSigning.Service
{
    public static class BatchedSigning
    {

        public static string GetTempFolder()
        {
            return Path.Combine(Path.GetTempPath(), "townsuite", "codesigning");
        }

        public static async Task<IResult> Sign(Stream body, Settings settings, ILogger logger, bool isDetachedSigning)
        {
            string id = Guid.NewGuid().ToString();

            var workingFolder = new DirectoryInfo(Path.Combine(GetTempFolder(), id));
            string workingFilePath = System.IO.Path.Combine(workingFolder.FullName, $"{id}.workingfile");
            try
            {
                if (!workingFolder.Exists)
                {
                    workingFolder.Create();
                }

                await using (var fileStream = new FileStream(workingFilePath, FileMode.Create))
                {
                    await body.CopyToAsync(fileStream);
                }

                // how to determine if this is just a hash file needs to be signed or a full file?


                BackgroundQueue.Instance.QueueThread(async () =>
                {
                    try
                    {
                        using var signer = new Signer(settings, logger);
                        await Queuing.semaphore.WaitAsync();
                        var results = await signer.SignAsync(workingFilePath);

                        if (results.IsSigned)
                        {
                            await File.WriteAllTextAsync(System.IO.Path.Combine(workingFolder.FullName, $"{id}.signed"), "true");
                        }
                        else
                        {
                            await File.WriteAllTextAsync(System.IO.Path.Combine(workingFolder.FullName, $"{id}.error"), results.Message);
                        }
                    }
                    catch (Exception ex)
                    {
                        await File.WriteAllTextAsync(System.IO.Path.Combine(workingFolder.FullName, $"{id}.error"), ex.Message);
                        logger.LogError(ex, $"Failed to sign file {workingFilePath}");
                        CleanupDir(workingFolder, logger);
                    }
                    finally
                    {
                        Queuing.semaphore.Release();
                    }
                });

                return Results.Ok(id);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "/sign/batch POST failure");
                return Results.Problem(title: "Failure accept", detail: ex.Message ?? "", statusCode: 500);
            }
        }

        public static async Task<IResult> Get(string id, ILogger logger)
        {

            var workingFolder = new DirectoryInfo(Path.Combine(GetTempFolder(), id));

            if (!workingFolder.Exists)
            {
                return Results.Problem(title: "Not Found", detail: "The id was not found", statusCode: 404);
            }

            if (System.IO.File.Exists(System.IO.Path.Combine(workingFolder.FullName, $"{id}.signed")))
            {
                var workingFile = System.IO.Path.Combine(workingFolder.FullName, $"{id}.workingfile");
                var fileStream = new TempFileStream(workingFile, workingFolder);
                return Results.Stream(fileStream);
            }

            if (System.IO.File.Exists(System.IO.Path.Combine(workingFolder.FullName, $"{id}.error")))
            {
                return Results.Problem(title: "Failure to sign", detail: await File.ReadAllTextAsync(System.IO.Path.Combine(workingFolder.FullName, $"{id}.error")), statusCode: 500);
            }

            return Results.Problem(title: "Not Signed", detail: "The file has not been signed yet", statusCode: 425);
        }

        static void CleanupDir(DirectoryInfo dir, ILogger logger)
        {
            try
            {
                dir.Delete(true);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"failed to cleanup dir {dir}");
            }
        }
    }
}
