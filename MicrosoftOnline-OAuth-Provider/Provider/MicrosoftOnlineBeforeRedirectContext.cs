//  Copyright 2014 Stefan Negritoiu. See LICENSE file for more information.

using System;
using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.MicrosoftOnline
{
    /// <summary>
    /// Context passed when a Challenge causes a redirect to authorize endpoint in the MicrosoftOnline OAuth 2.0 middleware
    /// </summary>
    public class MicrosoftOnlineBeforeRedirectContext : BaseContext<MicrosoftOnlineAuthenticationOptions>
    {
        /// <summary>
        /// Creates a new context object.
        /// </summary>
        /// <param name="context">The OWIN request context</param>
        /// <param name="options">The MicrosoftOnline middleware options</param>
        public MicrosoftOnlineBeforeRedirectContext(IOwinContext context, MicrosoftOnlineAuthenticationOptions options)
            : base(context, options) 
        {
        }
    }
}
