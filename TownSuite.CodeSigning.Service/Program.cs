using TownSuite.CodeSigning.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using System.Threading;
using System.Reflection;
using Microsoft.Extensions.Logging;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHealthChecks();
builder.Services.AddSingleton<Settings>(s => builder.Configuration.GetSection("Settings").Get<Settings>()!);
builder.WebHost.UseKestrel(o =>
{
    var settings = builder.Configuration.GetSection("Settings").Get<Settings>()!;
    o.Limits.MaxRequestBodySize = settings.MaxRequestBodySize;
});

var jwtSettings = builder.Configuration.GetSection("JWT").Get<JwtSettings>();

if (jwtSettings != null && !string.IsNullOrWhiteSpace(jwtSettings.Secret) &&
    !string.Equals(jwtSettings.Secret, "PLACEHOLDER", StringComparison.OrdinalIgnoreCase))
{
    var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Secret));
    builder.Services.AddAuthentication(options => { options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme; })
        .AddJwtBearer(options =>
        {
            options.SaveToken = true;
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidIssuer = jwtSettings.ValidIssuer,
                ValidAudience = jwtSettings.ValidAudience,
                IssuerSigningKey = symmetricSecurityKey
            };
        });
    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy(jwtSettings.PolicyName, policy =>
        {
            policy.AuthenticationSchemes.Add(JwtBearerDefaults.AuthenticationScheme);
            policy.RequireAuthenticatedUser();
        });
        options.DefaultPolicy = options.GetPolicy(jwtSettings.PolicyName);
        options.FallbackPolicy = options.DefaultPolicy;
    });
}

LogSetup(builder);

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseHttpsRedirection();

var log = app.Services.GetService<ILogger>();

string workingfolder = BatchedSigning.GetTempFolder();
InitializeWorkingFolder(workingfolder, log);

app.UseExceptionHandler(exceptionHandlerApp
    => exceptionHandlerApp.Run(async context
        => await Results.Problem()
                     .ExecuteAsync(context)));

app.MapPost("/sign", async (HttpRequest request, Settings settings, ILogger logger) =>
{
    // Obsolete, only kept in place for backwards compatibility
    bool isDetachedSigning = IsDetachedSigningRequest(request);
    var workingFilePath = new FileInfo(Path.Combine(BatchedSigning.GetTempFolder(), Guid.NewGuid().ToString()));
    try
    {
        await using (var fileStream = new FileStream(workingFilePath.FullName, FileMode.Create))
        {
            await request.Body.CopyToAsync(fileStream);
        }

        using var signer = new Signer(settings, logger);
        await Queuing.semaphore.WaitAsync();
        var results = await signer.SignAsync(workingFilePath.FullName);

        if (results.IsSigned)
        {
            // do not change to a filestream, as the filestream will be disposed before the file is returned
            var file = await File.ReadAllBytesAsync(workingFilePath.FullName);
            return Results.File(file);
        }
        return Results.Problem(title: "Failure to sign", detail: results.Message, statusCode: 500);
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "/sign failure");
        return Results.Problem(title: "Failure to sign", detail: ex.Message ?? "", statusCode: 500);
    }
    finally
    {
        Queuing.semaphore.Release();
        Cleanup(workingFilePath, logger);
    }
});
app.MapPost("/sign/batch", async (HttpRequest request, Settings settings, ILogger logger) =>
{
    bool isDetachedSigning = IsDetachedSigningRequest(request);
    return await BatchedSigning.Sign(request.Body, settings, logger, isDetachedSigning);
});

app.MapGet("/sign/batch", async (ILogger logger, string id) =>
{
    return await BatchedSigning.Get(id, logger);
});


app.MapHealthChecks("/healthz");
app.Run();

static void Cleanup(FileInfo workingFilePath, ILogger logger)
{
    try
    {
        workingFilePath.Delete();
    }
    catch(Exception ex)
    {
        logger.LogError(ex, $"failed to cleanup file {workingFilePath}");
    }
}


static void InitializeWorkingFolder(string workingfolder, ILogger logger)
{
    try
    {
        if (Directory.Exists(workingfolder))
        {
            Directory.Delete(workingfolder, true);
        }
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "InitializeWorkingFolder failed to delete the old working folder");
    }

    if (!Directory.Exists(workingfolder))
    {
        Directory.CreateDirectory(workingfolder);
    }
}

static void LogSetup(WebApplicationBuilder builder)
{
    string externalLogAssemblyPath = builder.Configuration.GetSection("ExternalLogsAssemblyFilePath").Value;
    string logFile = builder.Configuration.GetSection("LogFile").Value;
    if (!string.IsNullOrWhiteSpace(externalLogAssemblyPath))
    {
        string className = builder.Configuration.GetSection("ExternalLogsAssemblyClassName").Value;
        string functionName = builder.Configuration.GetSection("ExternalLogsAssemblyFunctionName").Value;

        AppDomain.CurrentDomain.AssemblyResolve += CurrentDomain_AssemblyResolve;

        var assembly = Assembly.LoadFrom(externalLogAssemblyPath);
        var externalLogsHelperType = assembly.GetType(className);
        var addLoggerMethod = externalLogsHelperType.GetMethod(functionName, BindingFlags.Static | BindingFlags.Public);

        builder.Services.AddLogging(configure =>
        {
            configure.ClearProviders();

            addLoggerMethod.Invoke(null, new object[] { configure, builder.Configuration });

        })
       .Configure<LoggerFilterOptions>(options =>
       {
           options.MinLevel = Microsoft.Extensions.Logging.LogLevel.Information;
       });
    }
    else
    {
        builder.Services.AddLogging(configure =>
        {
            configure.ClearProviders();
            configure.AddConsole();
        })
        .Configure<LoggerFilterOptions>(options => options.MinLevel = Microsoft.Extensions.Logging.LogLevel.Information);
    }

    builder.Services.AddSingleton<Microsoft.Extensions.Logging.ILogger>(s =>
    {
        return s.GetRequiredService<Microsoft.Extensions.Logging.ILoggerFactory>().CreateLogger("TownSuite");
    });
}

static Assembly CurrentDomain_AssemblyResolve(object sender, ResolveEventArgs args)
{
    string assemblyPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, args.Name.Split(',')[0] + ".dll");
    if (File.Exists(assemblyPath))
    {
        return Assembly.LoadFrom(assemblyPath);
    }
    return null;
}

static bool IsDetachedSigningRequest(HttpRequest request)
{
    return request.Headers.TryGetValue("X-DETACHED-SIGNING", out var detachedHeader) && detachedHeader == "indeed";
}