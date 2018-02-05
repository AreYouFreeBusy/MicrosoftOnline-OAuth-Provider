//  Copyright 2014 Stefan Negritoiu. See LICENSE file for more information.

using System;
using System.Threading.Tasks;

namespace Owin.Security.Providers.AzureAD
{
    /// <summary>
    /// Specifies callback methods which the <see cref="AzureADAuthenticationMiddleware"></see> invokes to enable developer control over the authentication process. />
    /// </summary>
    public interface IAzureADAuthenticationProvider
    {
        /// <summary>
        /// Invoked whenever AzureAD successfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task Authenticated(AzureADAuthenticatedContext context);

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task ReturnEndpoint(AzureADReturnEndpointContext context);

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the AzureAD middleware, before the actual redirect.
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge </param>
        void BeforeRedirect(AzureADBeforeRedirectContext context);

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the AzureAD middleware
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge </param>
        void ApplyRedirect(AzureADApplyRedirectContext context);
    }
}