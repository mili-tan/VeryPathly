using System.Net;
using System.Security.Cryptography.X509Certificates;
using AspNetCoreRateLimit;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ProxyKit;

namespace VeryPathly
{
    internal class Program
    {
        public static string TargetUrl = "http://127.0.0.1:2000";
        public static string ListenUrl = "http://127.0.0.1:8080";
        public static bool UseRateLimiting = false;
        public static bool UseCors = false;
        public static bool UsePath = true;
        public static int TimeOut = 60;
        public static List<string> AuthorizedPrefix = new List<string>();

        static void Main(string[] args)
        {
            var isZh = Thread.CurrentThread.CurrentCulture.Name.Contains("zh");
            var cmd = new CommandLineApplication
            {
                Name = "VeryPathly",
                Description = "VeryPathly - Very simple URL auth reverse proxy." +
                              Environment.NewLine +
                              $"Copyright (c) {DateTime.Now.Year} AS-Lab. Code released under the MIT License"
            };
            cmd.HelpOption("-?|-h|--help|-he");
            var fileArgument = cmd.Argument("file",
                isZh ? "授权前缀 CSV（第一列）" : "Authorized Prefix CSV（First column）", multipleValues: false);

            var ipOption = cmd.Option<string>("-l|--listen <IPEndPoint>",
                isZh ? "监听的地址与端口。" : "Set server listening address and port <http://127.0.0.1:8080>",
                CommandOptionType.SingleValue);
            var targetOption = cmd.Option<string>("-t|--target <Url>",
                isZh ? "目标地址与端口。" : "Set target address and port <http://127.0.0.1:2000>",
                CommandOptionType.SingleValue);

            var httpsOption = cmd.Option("-s|--https",
                isZh ? "启用 HTTPS。（默认自签名，不推荐）" : "Set enable HTTPS (Self-signed by default, not recommended)",
                CommandOptionType.NoValue);
            var pemOption = cmd.Option<string>("-pem|--pem-file <FilePath>",
                isZh ? "PEM 证书路径。 <./cert.pem>" : "Set your pem certificate file path <./cert.pem>",
                CommandOptionType.SingleOrNoValue);
            var keyOption = cmd.Option<string>("-key|--key-file <FilePath>",
                isZh ? "PEM 证书密钥路径。 <./cert.key>" : "Set your pem certificate key file path <./cert.key>",
                CommandOptionType.SingleOrNoValue);
            var crosOption = cmd.Option("-c|--cors",
                isZh ? "启用 CORS。" : "Set enable CORS",
                CommandOptionType.NoValue);
            var pathOption = cmd.Option("--use-path",
                isZh ? "使用路径前缀而不是 Host 前缀鉴权。" : "Use path prefix instead of host prefix",
                CommandOptionType.NoValue);
            var useRateLimitOption = cmd.Option("--use-rate-limit",
                isZh ? "启用请求速率限制。(请在 ipratelimiting.json 中设置)" : "Enable request rate limiting (with ipratelimiting.json)",
                CommandOptionType.NoValue);
            var timeOutOption = cmd.Option<int>("-o|--timeout <Seconds>",
                isZh ? "请求超时时间(秒)。" : "Set request timeout in seconds <15>",
                CommandOptionType.SingleValue);

            cmd.OnExecute(() =>
            {
                if (ipOption.HasValue()) ListenUrl = ipOption.Value()!;
                if (targetOption.HasValue()) TargetUrl = targetOption.Value()!;
                if (crosOption.HasValue()) UseCors = true;
                if (useRateLimitOption.HasValue()) UseRateLimiting = true;
                if (pathOption.HasValue()) UsePath = true;
                if (timeOutOption.HasValue()) TimeOut = timeOutOption.ParsedValue;
                if (fileArgument.Values.Count == 0)
                {
                    cmd.ShowHelp();
                    return;
                }

                var lines = File.ReadAllLines(fileArgument.Value!);
                foreach (var line in lines)
                {
                    var parts = line.Split(',');
                    AuthorizedPrefix.Add(parts.First());
                }

                var host = new WebHostBuilder()
                    .UseKestrel()
                    .UseContentRoot(AppDomain.CurrentDomain.SetupInformation.ApplicationBase!)
                    .ConfigureServices(services =>
                    {
                        services.AddRouting();
                        services.AddProxy(httpClientBuilder =>
                            httpClientBuilder.ConfigureHttpClient(client =>
                                client.Timeout = TimeSpan.FromSeconds(TimeOut)));

                        try
                        {
                            if (!UseRateLimiting) return;
                            var config = new ConfigurationBuilder().AddJsonFile("ipratelimiting.json").Build();
                            services.AddMemoryCache();
                            services.Configure<IpRateLimitOptions>(config.GetSection("IpRateLimiting"));
                            services.AddInMemoryRateLimiting();
                            services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e);
                        }
                    })
                    .ConfigureKestrel(options =>
                    {
                        var uri = new Uri(ListenUrl);
                        options.Listen(new IPEndPoint(IPAddress.Parse(uri.Host), uri.Port == 0 ? 2000 : uri.Port),
                            listenOptions =>
                            {
                                listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
                                if (httpsOption.HasValue()) listenOptions.UseHttps();
                                if (pemOption.HasValue() && keyOption.HasValue())
                                    listenOptions.UseHttps(X509Certificate2.CreateFromPem(
                                        File.ReadAllText(pemOption.Value()!), File.ReadAllText(keyOption.Value()!)));
                            });
                    }).Configure(app =>
                    {
                        if (UseRateLimiting) app.UseMiddleware<IpRateLimitMiddleware>().UseIpRateLimiting();
                        app.Use(async (context, next) =>
                        {
                            if (UseCors)
                            {
                                context.Response.Headers.TryAdd("Access-Control-Allow-Origin", "*");
                                context.Response.Headers.TryAdd("Access-Control-Allow-Methods", "*");
                                context.Response.Headers.TryAdd("Access-Control-Allow-Headers", "*");
                                context.Response.Headers.TryAdd("Access-Control-Allow-Credentials", "*");
                            }

                            var prefix = UsePath
                                ? context.Request.Path.Value?.TrimStart('/').Split("/").First()
                                : context.Request.Host.Value.Split(".").First();

                            if (prefix == null || !AuthorizedPrefix.Contains(prefix))
                            {
                                context.Response.StatusCode = 404;
                                await context.Response.WriteAsync("Not Found");
                                return;
                            }

                            context.Items["Token"] = prefix;
                            await next.Invoke();
                        });

                        app.Map(string.Empty, svr =>
                        {
                            svr.RunProxy(async context =>
                            {
                                context.Request.PathBase = context.Request.PathBase.Value?.Replace($"/{context.Items["Token"]}/", "/");
                                context.Request.Path = context.Request.Path.Value?.Replace($"/{context.Items["Token"]}/", "/");
                                var response = await context
                                    .ForwardTo(
                                        new Uri(TargetUrl))
                                    .Send();
                                response.Headers.Add("X-Forwarder-By", "VeryPathly-By-ASLab/0.1");
                                return response;
                            });
                        });
                    }).Build();

                host.Run();
            });

            cmd.Execute(args);
        }
    }
}
