using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Advanced.Security.V3.Cryptography.Hashing;
using Advanced.Security.V3.Data.PIIStorage;
using Advanced.Security.V3.Cryptography;
using Advanced.Security.V3.Cryptography.Symmetric;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.AspNetCore.Mvc;
using Advanced.Security.V3.Data.Primary;
using Advanced.Security.V3.Logging;
using Advanced.Security.V3.Authentication;
using Microsoft.AspNetCore.Authorization;
using Advanced.Security.V3.Authorization;
using Microsoft.AspNetCore.Antiforgery;
using Advanced.Security.V3.AntiCSRF;

namespace Advanced.Security.V3
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
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));
            AddDefaultIdentity<IdentityUser>(services, options => options.SignIn.RequireConfirmedAccount = true)
                .AddRoles<IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>();
            services.AddAuthorization(o =>
            {
                o.AddPolicy("RequireAuthorship", policy => policy.RequireClaim("IsAuthor"));
                o.AddPolicy("MinimumAccessLevelManager", policy => policy.Requirements.Add(new MinimumAccessLevelRequirement("Manager")));
            });
            services.AddControllersWithViews(o => o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));
            services.AddRazorPages().AddRazorPagesOptions(options =>
            {
                options.Conventions.AuthorizeFolder("/");
            });

            //services.AddAuthentication().AddTwitter(o =>
            //{
            //    //Please DON'T store your key and secret here!
            //    o.ConsumerKey = "<< YOUR KEY >>";
            //    o.ConsumerSecret = "<< YOUR SECRET >>>";
            //    o.RetrieveUserDetails = true;
            //});

            services.AddScoped<PiiDbContext>(_ => new PiiDbContext(Configuration.GetConnectionString("DefaultConnection")));
            services.AddSingleton<ISecretStore, SecretStore>();
            services.AddScoped<IHasher, Hasher>();
            services.AddScoped<ISymmetricEncryptor, SymmetricEncryptor>();
            services.AddScoped<ICryptoStoreSimulator, CryptoStoreSimulator>();
            services.AddScoped<ISecurityLogger, SecurityLogger>();

            services.Replace(new ServiceDescriptor(
                    serviceType: typeof(IPasswordHasher<IdentityUser>),
                    implementationType: typeof(Hasher),
                    ServiceLifetime.Scoped));

            services.Replace(new ServiceDescriptor(
                    serviceType: typeof(IUserStore<IdentityUser>),
                    implementationType: typeof(CustomUserStore),
                    ServiceLifetime.Scoped));

            services.Replace(new ServiceDescriptor(
                serviceType: typeof(SignInManager<IdentityUser>),
                implementationType: typeof(CustomSignInManager),
                ServiceLifetime.Scoped));

            services.Replace(new ServiceDescriptor(
                serviceType: typeof(UserManager<IdentityUser>),
                implementationType: typeof(CustomUserManager),
                ServiceLifetime.Scoped));

            services.AddSingleton<IAuthorizationHandler, MinimumAccessLevelHandler>();

            services.AddSingleton<IAntiforgeryAdditionalDataProvider, CSRFExpirationCheck>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env) //, ILoggerFactory logFactory)
        {
            if (env.IsDevelopment())
            {
                //logFactory.AddProvider(new CustomLogFileProvider());
                app.UseExceptionHandler("/Home/Error");
                //app.UseExceptionHandler("/Error");

                //app.UseDeveloperExceptionPage();
                //app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            //app.Use(async (context, next) => {
            //    context.Response.Headers.Add("FromStartup", "true");

            //    await next();
            //});

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    //pattern: "{controller=Home}/{action=Index}/{id?}");
                    pattern: "{controller=Home}/{action=Index}/{id?}").RequireAuthorization();
                endpoints.MapRazorPages();
            });
        }

        public static IdentityBuilder AddDefaultIdentity<TUser>(IServiceCollection services, Action<IdentityOptions> configureOptions) where TUser : class
        {
            services.AddAuthentication(o =>
            {
                o.DefaultScheme = IdentityConstants.ApplicationScheme;
                o.DefaultSignInScheme = IdentityConstants.ExternalScheme;
            })
            .AddIdentityCookies(o => {
                o.ApplicationCookie.Configure(o => { o.Events = new SessionTokenCookieEvents(); });
            });

            //services.AddAuthorization();

            return services.AddIdentityCore<TUser>(o =>
            {
                o.Stores.MaxLengthForKeys = 128;
                configureOptions?.Invoke(o);
            })
                .AddDefaultUI()
                .AddDefaultTokenProviders();
        }
    }
}
