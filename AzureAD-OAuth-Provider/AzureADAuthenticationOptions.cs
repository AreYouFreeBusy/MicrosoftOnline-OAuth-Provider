//  Copyright 2014 Stefan Negritoiu. See LICENSE file for more information.

using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.AzureAD
{
    public class AzureADAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        ///     Initializes a new <see cref="AzureADAuthenticationOptions" />
        /// </summary>
        public AzureADAuthenticationOptions() : base(Constants.DefaultAuthenticationType) 
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-azuread");
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            RequestLogging = false;
        }

        /// <summary>
        ///     Gets or sets the AzureAD supplied Application Key
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the AzureAD supplied Application Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        ///     The Resource Uri for which a token is being requested.
        /// </summary>
        public string Resource { get; set; }

        /// <summary>
        ///     Gets or sets the kind of Microsoft Account or the tenant targeted for authentication
        /// </summary>
        private string _tenant;
        public string Tenant {
            get {
                return _tenant ?? MicrosoftAccountType.All;
            }
            set {
                _tenant = value;
            }
        }

        /// <summary>
        ///     Controls whether request content is logged (verbose level). 
        ///     Not meant for use in production since data is sensitive (client secret, etc.).
        /// </summary>
        public bool RequestLogging { get; set; }

        /// <summary>
        ///     Controls whether response content is logged (verbose level). 
        ///     Not meant for use in production since data is sensitive (token, etc.).
        /// </summary>
        public bool ResponseLogging { get; set; }

        /// <summary>
        ///     Controls whether error responses are logged. 
        /// </summary>
        public bool ErrorLogging { get; set; }

        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to AzureAD
        /// </summary>
        /// <value>
        ///     The pinned certificate validator.
        /// </value>
        /// <remarks>
        ///     If this property is null then the default certificate checks are performed,
        ///     validating the subject name and if the signing chain is a trusted party.
        /// </remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        ///     The HttpMessageHandler used to communicate with AzureAD.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with AzureAD.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-azuread".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        ///     Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        /// <summary>
        ///     Gets or sets the <see cref="IAzureADAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IAzureADAuthenticationProvider Provider { get; set; }

        /// <summary>
        ///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
        ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        ///     Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
    }
}