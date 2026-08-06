using TownSuite.CodeSigning.Service;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Reflection;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<SigningHealthCheck>();
builder.Services.AddHealthChecks()
    // Liveness: the process is up and able to respond. No external dependencies.
    .AddCheck("self", () => Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy("Service is live."), tags: new[] { "live" })
    // Readiness: verifies code signing actually works by signing a canary file.
    .AddCheck<SigningHealthCheck>("signing", tags: new[] { "ready" });
builder.Services.AddSingleton<Settings>(s => builder.Configuration.GetSection("Settings").Get<Settings>());
builder.Services.AddSingleton<StatusService>();
builder.WebHost.UseKestrel(o =>
{
    var settings = builder.Configuration.GetSection("Settings").Get<Settings>();
    o.Limits.MaxRequestBodySize = settings.MaxRequestBodySize;

    if (settings.SignToolOptions.Contains("testcert"))
    {
        Certs.CreateTestCert(Path.Combine(AppContext.BaseDirectory, "testcert.pfx"), "password");
    }
});
builder.Services.AddHostedService<CleanerService>();
// Keeps the readiness signing canary warm so health/status probes never wait on signtool.
builder.Services.AddHostedService<SigningCanaryService>();


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

Queuing.SetSemaphore(builder.Configuration.GetSection("Settings").Get<Settings>());

// Configure the HTTP request pipeline.

app.UseHttpsRedirection();
app.UseDefaultFiles();
app.UseStaticFiles();

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

    var workingFilePath = new FileInfo(Path.Combine(BatchedSigning.GetTempFolder(), Guid.NewGuid().ToString()));
    try
    {
        await using (var fileStream = new FileStream(workingFilePath.FullName, FileMode.Create))
        {
            await request.Body.CopyToAsync(fileStream);
        }

        var signer = new Signer(settings, logger);
        await Queuing.Semaphore.WaitAsync();
        var results = await signer.SignAsync(workingFilePath.Directory.FullName, [workingFilePath.FullName]);

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
        Queuing.Semaphore.Release();
        Cleanup(workingFilePath, logger);
    }
});
app.MapPost("/sign/batch", async (HttpRequest request, Settings settings, ILogger logger) =>
{
    var headers = request.Headers.ToDictionary();
    ISigner signer = GetSigner(request, settings, logger,  headers);
    return await BatchedSigning.Sign(headers, request.Body, logger, signer);
});

app.MapGet("/sign/batch", async (HttpRequest request, Settings settings, ILogger logger, string id) =>
{
    var headers = request.Headers.ToDictionary();
    ISigner signer = GetSigner(request, settings, logger, headers);

    return await BatchedSigning.Get(headers, id, signer);
});

static ISigner GetSigner(HttpRequest request, Settings settings, ILogger logger, Dictionary<string, Microsoft.Extensions.Primitives.StringValues> headers)
{
    ISigner signer = new Signer(settings, logger);
    if (IsDetachedRequest(headers))
    {
        signer = new SignerDetached(settings, logger);
    }
    return signer;
}

// /healthz runs every check (backwards compatible). /health/live is liveness only,
// /health/ready fails when code signing is failing.
app.MapHealthChecks("/healthz").AllowAnonymous();
app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("live")
}).AllowAnonymous();
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready")
}).AllowAnonymous();

// Anonymous by design: operators need a status view reachable without a token, matching the
// health endpoints above. See Readme.md "Admin status dashboard" for the trade-off.
app.MapGet("/admin/status", async (StatusService status, HealthCheckService health, CancellationToken ct) =>
    Results.Ok(await status.GetStatusAsync(health, ct)))
   .AllowAnonymous();

app.Run();

static bool IsDetachedRequest(Dictionary<string, Microsoft.Extensions.Primitives.StringValues> headers)
{
    if (headers.TryGetValue("X-Detached", out var val))
    {
        return string.Equals(val, "1") || string.Equals(val, "true", StringComparison.OrdinalIgnoreCase);
    }
    return false;
}

static void Cleanup(FileInfo workingFilePath, ILogger logger)
{
    try
    {
        workingFilePath.Delete();
    }
    catch (Exception ex)
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
