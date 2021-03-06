﻿//  Copyright 2015 Stefan Negritoiu. See LICENSE file for more information.

using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.MicrosoftOnline
{
    public class MicrosoftOnlineAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        ///     Initializes a new <see cref="MicrosoftOnlineAuthenticationOptions" />
        /// </summary>
        public MicrosoftOnlineAuthenticationOptions() : base(Constants.DefaultAuthenticationType) 
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-microsoftonline");
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Scope = new List<string>();
            AdminConsent = false;
            RequestLogging = false;
        }

        /// <summary>
        ///     Gets or sets the MicrosoftOnline supplied Application Key
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the MicrosoftOnline supplied Application Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        ///     One of MicrosoftOnline.Environment values
        /// </summary>
        public string Environment { get; set; }

        /// <summary>
        ///     A list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; private set; }

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
        ///     True to request admin consent flow
        /// </summary>
        public bool AdminConsent { get; set; }

        /// <summary>
        ///     Method that should be used to send the resulting authorization_code back to your app. 
        ///     Can be one of 'query', 'form_post', or 'fragment'.
        /// </summary>
        public string ResponseMode { get; set; }

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
        ///     in back channel communications belong to MicrosoftOnline
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
        ///     The HttpMessageHandler used to communicate with MicrosoftOnline.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with MicrosoftOnline.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-microsoftonline".
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
        ///     Gets or sets the <see cref="IMicrosoftOnlineAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IMicrosoftOnlineAuthenticationProvider Provider { get; set; }

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