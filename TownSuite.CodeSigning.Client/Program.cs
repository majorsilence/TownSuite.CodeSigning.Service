using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text;
using TownSuite.CodeSigning.Client;

string[] filepaths = null;
string folder = string.Empty;
string url = string.Empty;
string baseurl = string.Empty;
string token = string.Empty;
bool quickFail = false;
bool ignoreFailures = false;
int timeoutInMs = 10000;
int batchTimeoutInSeconds = 1200;
bool detachedSignature = false;
DetachedSignatureArgs signToolArgs = new DetachedSignatureArgs();

for (int i = 0; i < args.Length; i++)
{
    if (string.Equals(args[i], "-file", StringComparison.InvariantCultureIgnoreCase))
    {
        filepaths = args[i + 1].Split(";");
    }
    else if (string.Equals(args[i], "-folder", StringComparison.InvariantCultureIgnoreCase))
    {
        folder = args[i + 1];
    }
    else if (string.Equals(args[i], "-url", StringComparison.InvariantCultureIgnoreCase))
    {
        url = args[i + 1];
    }
    else if (string.Equals(args[i], "-baseurl", StringComparison.InvariantCultureIgnoreCase))
    {
        baseurl = args[i + 1];
    }
    else if (string.Equals(args[i], "-token", StringComparison.InvariantCultureIgnoreCase))
    {
        token = args[i + 1];
    }
    else if (string.Equals(args[i], "-tokenfile", StringComparison.InvariantCultureIgnoreCase))
    {
        string tokenFile = args[i + 1];
        token = await System.IO.File.ReadAllTextAsync(tokenFile);
    }
    else if (string.Equals(args[i], "-quickfail", StringComparison.InvariantCultureIgnoreCase))
    {
        quickFail = true;
    }
    else if (string.Equals(args[i], "-ignorefailures", StringComparison.InvariantCultureIgnoreCase))
    {
        ignoreFailures = true;
    }
    else if (string.Equals(args[i], "-timeout", StringComparison.InvariantCultureIgnoreCase))
    {
        if (!int.TryParse(args[i + 1], out timeoutInMs))
        {
            Console.WriteLine($"-timeout value failed to parse.  defaulting to {timeoutInMs}");
        }
    }
    else if (string.Equals(args[i], "-batchtimeout", StringComparison.InvariantCultureIgnoreCase))
    {
        if (!int.TryParse(args[i + 1], out batchTimeoutInSeconds))
        {
            Console.WriteLine($"-batchtimeout value failed to parse.  defaulting to {batchTimeoutInSeconds}");
        }
    }
    else if (string.Equals(args[i], "-detachedsignature", StringComparison.InvariantCultureIgnoreCase))
    {
        detachedSignature = true;
    }
    else if (string.Equals(args[i], "-signtool", StringComparison.InvariantCultureIgnoreCase))
    {
        signToolArgs.SigntoolPath = args[i + 1];
    }
    else if (string.Equals(args[i], "-signtool-detached-args", StringComparison.InvariantCultureIgnoreCase))
    {
        signToolArgs.SigntoolDetachedArgs = args[i + 1];
    }
    else if (string.Equals(args[i], "-help", StringComparison.InvariantCultureIgnoreCase)
             || string.Equals(args[i], "--help", StringComparison.InvariantCultureIgnoreCase)
             || string.Equals(args[i], "-h", StringComparison.InvariantCultureIgnoreCase)
             || string.Equals(args[i], "--h", StringComparison.InvariantCultureIgnoreCase)
             || string.Equals(args[i], "/?", StringComparison.InvariantCultureIgnoreCase)
            )
    {
        PrintHelp();
    }
}

if (string.IsNullOrWhiteSpace(baseurl))
{
    baseurl = url;
}


if (filepaths == null || filepaths.Length == 0)
{
    Console.WriteLine("-file must be set");
    PrintHelp();
    System.Environment.Exit(-1);
}

if (string.IsNullOrWhiteSpace(url))
{
    Console.WriteLine("-url must be set");
    PrintHelp();
    System.Environment.Exit(-1);
}

if (string.IsNullOrWhiteSpace(token))
{
    Console.WriteLine("-token must be set");
    PrintHelp();
    System.Environment.Exit(-1);
}


var client = new HttpClient
{
    Timeout = TimeSpan.FromMilliseconds(timeoutInMs)
};

//client.BaseAddress = new Uri(url);
if (!string.IsNullOrWhiteSpace(token))
{
    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
}


try
{
    bool failures = false;
    failures = await ProcessFiles(filepaths, url, quickFail, ignoreFailures);

    if (failures && !ignoreFailures)
    {
        Environment.Exit(-3);
    }
}
catch (Exception ex)
{
    Console.WriteLine(ex);
    if (!ignoreFailures)
    {
        Environment.Exit(-2);
    }
}
finally
{
    client?.Dispose();
}


void PrintHelp()
{
    Console.WriteLine();
    Console.WriteLine("Options");
    Console.WriteLine("-help --help -h --h /?");
    Console.WriteLine("-file \"path to dll or exe\"");
    Console.WriteLine("    the file path can contain multiple files by ; separating them.");
    Console.WriteLine("-folder \"the folder that the dll or exe are located\"");
    Console.WriteLine("    If this is set -file is assumed to just be a filename instead of a full path.");
    Console.WriteLine("-url \"url to signing server\"");
    Console.WriteLine("-token \"the auth token\" or -tokenfile \"path to plain text file holding token\"");
    Console.WriteLine("-quickfail if this is set the program will exit on the first faliure.");
    Console.WriteLine("-ignorefailures if this is set the program will ignore all errors and override quickfail.");
    Console.WriteLine("-timeout \"10000\"");
    Console.WriteLine("    Timeout is in ms.  Defaults to 10000.   This is per http request.");
    Console.WriteLine("");
    Console.WriteLine("-batchtimeout");
    Console.WriteLine("    The total time permitted for the whole batch");
    Console.WriteLine("    If not set the default is 1200 seconds.");
    Console.WriteLine("");
    Console.WriteLine("-detachedsignature");
    Console.WriteLine("    If this is set the program will " + Environment.NewLine +
        "        1. create the hash locally," + Environment.NewLine +
        "        2. send it to the server which will sign the hash, " + Environment.NewLine +
        "        3. and download the signed hash and apply it to the file." + Environment.NewLine+
        "        4. requires signtool to be available and a signtool template arg be passed in");
    Console.WriteLine("");
    Console.WriteLine("    -signtool \"path to signtool.exe\"");
    Console.WriteLine("");
    Console.WriteLine("    -signtool-detached-args \"sign /as /fd sha256 /p7s \"{HashFilePath}\" /tr http://timestamp.digicert.com /td sha256 \"{AssemblyFilePath}\"\"");
    Console.WriteLine("        signtool arguments to apply signed hash to file");
    Console.WriteLine("");
    Console.WriteLine("");
    Console.WriteLine("Example");
    Console.WriteLine(
        ".\\TownSuite.CodeSigning.Client.exe -file \"C:\\some\\file.dll\" -url \"https://localhost:5000/sign\" -token \"the token\"");
}


async Task<bool> ProcessFiles(string[] filepaths, string url, bool quickFail, bool ignoreFailures)
{
    List<string> files = FileHelpers.CreateFileList(filepaths, folder);

    SigningClient signer;
    if (detachedSignature)
    {
        if (string.IsNullOrWhiteSpace(signToolArgs.SigntoolPath) || string.IsNullOrWhiteSpace(signToolArgs.SigntoolDetachedArgs))
        {
            Console.WriteLine("When using detached signature you must specify the signtool path and the signtool detached args.");
            PrintHelp();
            Environment.Exit(-1);
        }
        signer = new SigningClientDetached(client, url, signToolArgs);
    }
    else
    {
        signer = new SigningClient(client, url);
    }

    bool signingServiceIsOnline = await signer.HealthCheck();
    if (!signingServiceIsOnline)
    {
        Environment.Exit(-2);
    }

    var uploadFailures = await signer.UploadFiles(quickFail, ignoreFailures, files.ToArray());
    if (uploadFailures.Length > 0)
    {
        foreach (var result in uploadFailures)
        {
            Console.WriteLine($"Failed to upload/sign file: {result.FailedFile}");
            Console.WriteLine(result.Message);
        }
        return true;
    }

    var downloadResults = await signer.DownloadSignedFiles(quickFail, ignoreFailures, batchTimeoutInSeconds);
    if (downloadResults.Length > 0)
    {
        foreach (var result in downloadResults)
        {
            Console.WriteLine($"Failed to download/sign file: {result.FailedFile}");
            Console.WriteLine(result.Message);
        }
        return true;
    }

    return false;
}
