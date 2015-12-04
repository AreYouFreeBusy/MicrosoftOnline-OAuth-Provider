//  Copyright 2015 Stefan Negritoiu. See LICENSE file for more information.

using System;

namespace Owin.Security.Providers.MicrosoftOnline
{
    public static class MicrosoftOnlineAuthenticationExtensions
    {
        public static IAppBuilder UseMicrosoftOnlineAuthentication(this IAppBuilder app, MicrosoftOnlineAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(MicrosoftOnlineAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseMicrosoftOnlineAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseMicrosoftOnlineAuthentication(new MicrosoftOnlineAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}