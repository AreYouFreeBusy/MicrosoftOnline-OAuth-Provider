//  Copyright 2014 Stefan Negritoiu. See LICENSE file for more information.

using System;

namespace Owin.Security.Providers.AzureAD
{
    public static class AzureADAuthenticationExtensions
    {
        public static IAppBuilder UseAzureADAuthentication(this IAppBuilder app, AzureADAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(AzureADAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseAzureADAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseAzureADAuthentication(new AzureADAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}