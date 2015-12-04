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
                // per https://msdn.microsoft.com/en-us/office/office365/howto/authentication-v2-token-reference
                Subject = TryGetValue(idTokenObj, "sub");
                ObjectId = TryGetValue(idTokenObj, "oid");
                TenantId = TryGetValue(idTokenObj, "tid");
                Upn = TryGetValue(idTokenObj, "upn");
                UserName = TryGetValue(idTokenObj, "preferred_username");
                Name = TryGetValue(idTokenObj, "name");
                GivenName = TryGetValue(idTokenObj, "given_name");
                FamilyName = TryGetValue(idTokenObj, "family_name");
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
        /// Gets the user's ID
        /// </summary>
        public string Subject { get; private set; }

        /// <summary>
        /// Gets the user's ID
        /// </summary>
        public string ObjectId { get; private set; }

        /// <summary>
        /// Gets the user's ID
        /// </summary>
        public string TenantId { get; private set;
        }

        /// <summary>
        /// Gets the user's UPN
        /// </summary>
        public string Upn { get; private set; }

        /// <summary>
        /// Gets the user's full name
        /// </summary>
        public string GivenName { get; private set; }
        
        /// <summary>
        /// Gets the user's full name
        /// </summary>
        public string FamilyName { get; private set; }

        /// <summary>
        /// Gets the user's full name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the user's full name
        /// </summary>
        public string UserName { get; private set; } 

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
