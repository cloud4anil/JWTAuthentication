using AuthenticationProvider.Core.Model;

using Microsoft.Extensions.DependencyInjection;
using System;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace AuthenticationProvider.Core.Configuration
{
    public static class AddAuthConfiguration
    {

        public static void AddAuth(this IServiceCollection services, IConfiguration configuration)
        {
            var key = Encoding.ASCII.GetBytes(Constants.Secret);
            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(x =>
            {
                x.RequireHttpsMetadata = false;
                x.SaveToken = true;
                x.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = Convert.ToBoolean(configuration["TokenParameters:ValidateIssuerSigningKey"]),
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = Convert.ToBoolean(configuration["TokenParameters:ValidateIssuer"]),
                    ValidateAudience = Convert.ToBoolean(configuration["TokenParameters:ValidateAudience"]),
                    ValidateLifetime = Convert.ToBoolean(configuration["TokenParameters:ValidateLifetime"]),
                    ClockSkew = TimeSpan.Zero
                };
                x.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                        {
                            context.Response.Headers.Add("Token-Expired", "true");
                        }
                        return Task.CompletedTask;
                    }
                };
            });
        }
    }
}
