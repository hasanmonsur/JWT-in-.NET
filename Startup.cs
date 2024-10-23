using jWtTokenWebApi.Auth;
using jWtTokenWebApi.Interfaces;
using jWtTokenWebApi.Models;
using jWtTokenWebApi.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace jWtTokenWebApi
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            services.AddOptions();
            services.Configure<Audience>(Configuration.GetSection("Audience"));
            services.AddControllers();
            var spgLink = Configuration.GetSection("SpgLink").Get<SpgLink>();
           // services.Configure<SpgLink>(Configuration.GetSection("SpgLink"));

            services.AddHttpClient("SpgClient", client =>
            {
                client.BaseAddress = new Uri(spgLink.SpgUrl);
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                client.DefaultRequestHeaders.Add("API_KEY", spgLink.SpgKey);
                client.DefaultRequestHeaders.Add("Authorization", spgLink.SpgAuth);
                client.Timeout = TimeSpan.FromSeconds(30);  // Set appropriate timeout
            });


            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Security", Version = "v1" });
                c.AddSecurityDefinition("BasicAuth", new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.Http,
                    Scheme = "Basic", // tried lowercase "basic" too.
                    Description = "Input your username and password to access this API",
                    In = ParameterLocation.Header,
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                    {
                        {
                            new OpenApiSecurityScheme
                            {
                                Reference = new OpenApiReference {
                                    Type = ReferenceType.SecurityScheme,
                                    Id = "BasicAuth" }
                            }, new List<string>() }
                    });
            });

            services.AddTransient<IUserService, UserService>();
            services.AddAuthentication("BasicAuth")
            .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>("BasicAuth", null);

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();

            }
            app.UseSwagger();
            app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Sbl.Security.Api v1"));

            app.UseRouting();
            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
