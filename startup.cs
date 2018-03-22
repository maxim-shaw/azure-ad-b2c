using AspNet.Plus.Infrastructure.Builder;
using Channelsis.Portal.Api.Builders;
using Channelsis.Portal.Api.IocModules;
using Channelsis.Portal.Api.Core.WebApi.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ReflectInsight.Extensions.Logging;
using System;
using System.Diagnostics;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Threading.Tasks;
using System.Text;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Globalization;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Channelsis.Portal.Api.ConfigOptions;

namespace Channelsis.Portal.Api.API
{
    public class Startup
    {
        private string _aadInstance;
        private string _tenant;
        private string _audience;
        private string _policy;
        private string _azureClientId;
        private string _aadValidationEndpoint;

        public IConfigurationRoot Configuration { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="Startup"/> class.
        /// </summary>
        /// <param name="env">The env.</param>
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();
            Configuration = builder.Build();

            _aadInstance = Configuration["Authentication:AzureAd:ida:AADInstance"];
            _tenant = Configuration["Authentication:AzureAd:ida:Tenant"];
            _audience = Configuration["Authentication:AzureAd:ida:Audience"];
            _policy = Configuration["Authentication:AzureAd:ida:Policy"];
            _azureClientId = Configuration["Authentication:AzureAd:ida:ClientId"];
            _aadValidationEndpoint = Configuration["Authentication:AzureAd:ida:AADValidationEndpoint"];
        }
        
        /// <summary>
        /// Configures the services.
        /// This method gets called by the runtime. Use this method to add services to the container.
        /// </summary>
        /// <param name="services">The services.</param>
        /// <returns></returns>
        public IServiceProvider ConfigureServices(IServiceCollection services)
        {
            services.AddCors();
            services.AddConfigurations(Configuration);
            services.AddExceptionInterceptManager();

            services.AddOptions();
            services.AddSwaggerDoc();

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.MetadataAddress = string.Format(_aadValidationEndpoint, _tenant, _policy);
                    options.SaveToken = true;
                    options.RequireHttpsMetadata = false;
                    options.Audience = _azureClientId;
                    options.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = AuthenticationFailed,
                        OnMessageReceived = MessageReceivedAsync,
                        //OnChallenge = Challenge,
                        OnTokenValidated = TokenValidated
                    };
                });

            // Register the IConfiguration instance which AzureOptions binds against.
            services.Configure<AzureOptions>(options => 
            {
                options.Audience = _audience;
                options.Policy = _policy;
                options.Tenant = _tenant;
                options.ValidationEndpoint = _aadValidationEndpoint;
            });
            services.AddWebApi();

            return services.AddDependencyInjections(new IocApiModule());
        }

        /// <summary>
        /// Configures the specified application.
        /// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        /// </summary>
        /// <param name="app">The application.</param>
        /// <param name="env">The env.</param>
        /// <param name="loggerFactory">The logger factory.</param>
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddReflectInsight("ReflectInsight.config");

            app.UseCors();
            app.UseExceptionIntercepts();
            app.UseResponseHeaders();
            app.UseAuthentication();
            app.UseMvc();
            app.UseSwaggerDoc();

            DisableApplicationInsightsOnDebug();
        }

        #region JwtBearer Authentication Events

        private Task AuthenticationFailed(AuthenticationFailedContext arg)
        {
            // For debugging purposes only!
            var s = $"AuthenticationFailed: {arg.Exception.Message}";
            arg.Response.ContentLength = s.Length;
            arg.Response.Body.Write(Encoding.UTF8.GetBytes(s), 0, s.Length);
            return Task.FromResult(0);
        }

        private async Task MessageReceivedAsync(MessageReceivedContext arg)
        {
            string aadInstance = Configuration["Authentication:AzureAd:ida:AADInstance"];

            string issuer = string.Empty;
            List<SecurityKey> signingTokens = null;
            DateTime stsMetadataRetrievalTime = DateTime.MinValue;

            var authHeader = arg.HttpContext.Request.Headers["Authorization"];

            if (String.IsNullOrEmpty(authHeader))
            {
                var authenticatiuonHeader = new AuthenticationHeaderValue("Bearer", $"authentication_uri=");
                arg.HttpContext.Response.Headers.Add("Bearer", "some value here.");
            }

            // 7 = (Bearer + " ").Length
            var token = authHeader.ToString().Substring(7);
            try
            {
                string stsDiscoveryEndpoint = string.Format(_aadValidationEndpoint, _tenant, _policy);
                var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint, 
                    new OpenIdConnectConfigurationRetriever());

                OpenIdConnectConfiguration config = null;
                config = await configManager.GetConfigurationAsync();

                issuer = config.Issuer;
                signingTokens = config.SigningKeys.ToList();

                stsMetadataRetrievalTime = DateTime.UtcNow;
            }
            catch(Exception ex)
            {
                // Log error
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidAudience = _audience,
                ValidIssuer = issuer,
                IssuerSigningKeys = signingTokens
            };
            var claimsPrincipal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
            // Check to see if Principal has a "new user" attribute.
            // IF TRUE THEN 
            //    Grab x-claims header if exists, add extra claim to the principal. 
            //    Call GraphAPI to extend new user claims.

            ((ClaimsIdentity)claimsPrincipal.Identity).AddClaim(new Claim("TenantId", "12345"));
            ((ClaimsIdentity)claimsPrincipal.Identity).AddClaim(new Claim("ABC-XYZ", "some-value"));

            Thread.CurrentPrincipal = claimsPrincipal;

            var ticket = new AuthenticationTicket(claimsPrincipal, arg.Scheme.Name);
            arg.Principal = claimsPrincipal;
            arg.HttpContext.User = claimsPrincipal;
            arg.Success();
            return;
        }

        private Task Challenge(JwtBearerChallengeContext arg)
        {
            return Task.CompletedTask;
        }

        private Task TokenValidated(TokenValidatedContext arg)
        {
            arg.Success();
            return Task.CompletedTask;
        }

        #endregion

        /// <summary>
        /// Disables the application insights on debug.
        /// </summary>
        [Conditional("DEBUG")]
        private static void DisableApplicationInsightsOnDebug()
        {
            TelemetryConfiguration.Active.DisableTelemetry = true;
        }

        private HttpResponseMessage BuildResponseErrorMessage(HttpStatusCode statusCode)
        {
            var responseMessage = new HttpResponseMessage(statusCode);
            return responseMessage;
        }
    }
}
