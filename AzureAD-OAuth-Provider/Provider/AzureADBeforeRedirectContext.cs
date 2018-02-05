//  Copyright 2014 Stefan Negritoiu. See LICENSE file for more information.

using System;
using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.AzureAD
{
    /// <summary>
    /// Context passed when a Challenge causes a redirect to authorize endpoint in the AzureAD OAuth 2.0 middleware
    /// </summary>
    public class AzureADBeforeRedirectContext : BaseContext<AzureADAuthenticationOptions>
    {
        /// <summary>
        /// Creates a new context object.
        /// </summary>
        /// <param name="context">The OWIN request context</param>
        /// <param name="options">The AzureAD middleware options</param>
        public AzureADBeforeRedirectContext(IOwinContext context, AzureADAuthenticationOptions options)
            : base(context, options) 
        {
        }
    }
}
