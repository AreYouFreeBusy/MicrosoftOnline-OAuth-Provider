//  Copyright 2015 Stefan Negritoiu. See LICENSE file for more information.

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.MicrosoftOnline
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class MicrosoftOnlineAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="MicrosoftOnlineAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">MicrosoftOnline Access token</param>
        public MicrosoftOnlineAuthenticatedContext(IOwinContext context, 
            JObject idTokenObj, string accessToken, string scope, string expires, string refreshToken) 
            : base(context)
        {
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue)) 
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            string[] scopeSeparators = new string[1] { " " };
            Scope = scope.Split(scopeSeparators, StringSplitOptions.RemoveEmptyEntries);

            if (idTokenObj != null) 
            {
                // per https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-tokens
                Subject = TryGetValue(idTokenObj, "sub");
                ObjectId = TryGetValue(idTokenObj, "oid");
                TenantId = TryGetValue(idTokenObj, "tid");
                Upn = TryGetValue(idTokenObj, "upn");
                UserName = TryGetValue(idTokenObj, "preferred_username");
                Email = TryGetValue(idTokenObj, "email");
                Name = TryGetValue(idTokenObj, "name");
                GivenName = TryGetValue(idTokenObj, "given_name");
                FamilyName = TryGetValue(idTokenObj, "family_name");
                AppId = TryGetValue(idTokenObj, "aud");
            }
        }

        /// <summary>
        /// Gets the MicrosoftOnline OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the scope for this MicrosoftOnline OAuth access token
        /// </summary>
        public string[] Scope { get; private set; }

        /// <summary>
        /// Gets the MicrosoftOnline access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; private set; }

        /// <summary>
        /// Gets the MicrosoftOnline OAuth refresh token
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the user's ID (unique across tenants; unique across applications)
        /// </summary>
        public string Subject { get; private set; }

        /// <summary>
        /// Gets the user's ID (unique across tenants; not unique across applications)
        /// </summary>
        public string ObjectId { get; private set; }

        /// <summary>
        /// Gets the tenant's ID
        /// </summary>
        public string TenantId { get; private set; }

        /// <summary>
        /// Gets the UPN
        /// </summary>
        public string Upn { get; private set; }

        /// <summary>
        /// Gets the display UPN 
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the email address
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        /// Gets the user's first name
        /// </summary>
        public string GivenName { get; private set; }
        
        /// <summary>
        /// Gets the user's last name
        /// </summary>
        public string FamilyName { get; private set; }

        /// <summary>
        /// Gets the user's display name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the application ID for which token was issued
        /// </summary>
        public string AppId { get; private set; }

        /// <summary>
        /// Per docs "tid" is fixed to 9188040d-6c67-4c5b-b112-36a304b66dad for personal MSA.
        /// </summary>
        public bool? IsPersonalMicrosoftAccount {
            get {
                return !string.IsNullOrEmpty(TenantId) ? 
                    (bool?)(TenantId == "9188040d-6c67-4c5b-b112-36a304b66dad") : 
                    null; 
            }
        }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
