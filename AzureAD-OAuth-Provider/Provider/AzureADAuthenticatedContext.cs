//  Copyright 2014 Stefan Negritoiu. See LICENSE file for more information.

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.AzureAD
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class AzureADAuthenticatedContext : BaseContext
    {
        private readonly string[] SCOPE_SEPARATOR = new string[] { " " };

        /// <summary>
        /// Initializes a <see cref="AzureADAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Azure AD Access token</param>
        public AzureADAuthenticatedContext(IOwinContext context, 
            string accessToken, string expires, string refreshToken, JObject response) 
            : base(context)
        {
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            // parse expires field
            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue)) 
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            // parse scope field
            string scope = response["scope"]?.Value<string>();
            Scope = scope != null ? scope.Split(SCOPE_SEPARATOR, StringSplitOptions.RemoveEmptyEntries) : new string[0];

            // parse resource field
            Resource = response["resource"]?.Value<string>();

            // parse pwd fields
            string pwdchange = response["pwd_url"]?.Value<string>();
            string pwdexpires = response["pwd_exp"]?.Value<string>();
            if (!String.IsNullOrEmpty(pwdexpires) &&
                Int32.TryParse(pwdexpires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue)) 
            {
                PasswordExpiresIn = TimeSpan.FromSeconds(expiresValue);
                PasswordChangeUrl = pwdchange;
            }

            // parse id_token as a Base64 url encoded JSON web token
            string idToken = response["id_token"].Value<string>();
            JObject idTokenObj = null;
            string[] segments;
            if (!String.IsNullOrEmpty(idToken) && (segments = idToken.Split('.')).Length == 3) {
                string payload = base64urldecode(segments[1]);
                if (!String.IsNullOrEmpty(payload)) idTokenObj = JObject.Parse(payload);
            }

            if (idTokenObj != null) 
            {
                // per https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-token-and-claims
                Subject = TryGetValue(idTokenObj, "sub");
                ObjectId = TryGetValue(idTokenObj, "oid");
                TenantId = TryGetValue(idTokenObj, "tid");
                Upn = TryGetValue(idTokenObj, "upn");
                UserName = TryGetValue(idTokenObj, "unique_name");
                Name = TryGetValue(idTokenObj, "name");
                GivenName = TryGetValue(idTokenObj, "given_name");
                FamilyName = TryGetValue(idTokenObj, "family_name");
                AppId = TryGetValue(idTokenObj, "appid");
            }
        }

        /// <summary>
        /// Gets the AzureAD OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the scope for this AzureAD OAuth access token
        /// </summary>
        public string[] Scope { get; private set; }

        /// <summary>
        /// Gets the resource for this AzureAD OAuth access token
        /// </summary>
        public string Resource { get; private set; }

        /// <summary>
        /// Gets the AzureAD access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; private set; }

        /// <summary>
        /// Gets the AzureAD OAuth refresh token
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
        /// 
        /// </summary>
        public TimeSpan? PasswordExpiresIn { get; private set; }
        
        /// <summary>
        /// 
        /// </summary>
        public string PasswordChangeUrl { get; private set; }

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


        /// <summary>
        /// Based on http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-08#appendix-C
        /// </summary>
        static string base64urldecode(string arg) 
        {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default: throw new System.Exception("Illegal base64url string!");
            }

            try {
                System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();
                return encoding.GetString(Convert.FromBase64String(s)); // Standard base64 decoder
            }
            catch (FormatException) {
                return null;
            }
        }
    }
}
