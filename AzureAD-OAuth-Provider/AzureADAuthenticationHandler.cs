//  Copyright 2014 Stefan Negritoiu. See LICENSE file for more information.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.AzureAD
{
    public class AzureADAuthenticationHandler : AuthenticationHandler<AzureADAuthenticationOptions>
    {
        // for endpoint docs see 
        // https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-oauth-code 
        private const string AuthorizeEndpointFormat = "https://login.microsoftonline.com/{0}/oauth2/authorize";
        private const string TokenEndpointFormat = "https://login.microsoftonline.com/{0}/oauth2/token";
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string UserInfoEndpoint = "https://graph.windows.net/me?api-version=1.6";
        private const string UserInfoResource = "https://graph.windows.net";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public AzureADAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }


        #region implement base class methods
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1) 
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null) {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                // Build up the body for the token request
                var body = new List<KeyValuePair<string, string>>();
                body.Add(new KeyValuePair<string, string>("grant_type", "authorization_code"));
                body.Add(new KeyValuePair<string, string>("code", code));
                body.Add(new KeyValuePair<string, string>("redirect_uri", redirectUri));
                body.Add(new KeyValuePair<string, string>("client_id", Options.ClientId));
                body.Add(new KeyValuePair<string, string>("client_secret", Options.ClientSecret));
                body.Add(new KeyValuePair<string, string>("resource", Options.Resource));

                // Request the token
                var httpRequest = new HttpRequestMessage(HttpMethod.Post, String.Format(TokenEndpointFormat, Options.Tenant)) {
                    Content = new FormUrlEncodedContent(body)
                };
                if (Options.RequestLogging) 
                {
                    _logger.WriteVerbose(httpRequest.ToLogString());
                }
                var httpResponse = await _httpClient.SendAsync(httpRequest);
                if (!httpResponse.IsSuccessStatusCode && Options.ErrorLogging) 
                {
                    _logger.WriteError(httpResponse.ToLogString());
                }
                else if (Options.ResponseLogging) 
                {
                    // Note: avoid using one of the Write* methods that takes a format string as input
                    // because the curly brackets from a JSON response will be interpreted as
                    // curly brackets for the format string and function will throw a FormatException
                    _logger.WriteVerbose(httpResponse.ToLogString());
                }
                httpResponse.EnsureSuccessStatusCode();
                string content = await httpResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                var tokenResponse = JsonConvert.DeserializeObject<JObject>(content);
                string accessToken = tokenResponse["access_token"].Value<string>();
                string expires = tokenResponse.Value<string>("expires_in");
                string refreshToken = tokenResponse.Value<string>("refresh_token");

                // get user info
                string userDisplayName = null;
                string userEmail = null;
                var userInfoAccessToken =
                    Options.Resource != UserInfoResource ? await GetUserInfoAccessToken(code) : accessToken;
                var userJson = await GetUserInfoAsync(userInfoAccessToken);
                if (userJson != null) 
                {
                    userDisplayName = userJson["displayName"]?.Value<string>();
                    userEmail = userJson["mail"]?.Value<string>();
                }

                var context = new AzureADAuthenticatedContext(Context, accessToken, expires, refreshToken, tokenResponse);
                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                if (!string.IsNullOrEmpty(context.ObjectId)) 
                {
                    context.Identity.AddClaim(
                        new Claim(ClaimTypes.NameIdentifier, context.ObjectId, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Upn)) 
                {
                    context.Identity.AddClaim(
                        new Claim(ClaimTypes.Upn, context.Upn, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(userEmail)) 
                {
                    context.Email = userEmail;
                    context.Identity.AddClaim(
                        new Claim(ClaimTypes.Email, userEmail, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.GivenName)) 
                {
                    context.Identity.AddClaim(
                        new Claim(ClaimTypes.GivenName, context.GivenName, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.FamilyName)) 
                {
                    context.Identity.AddClaim(
                        new Claim(ClaimTypes.Surname, context.FamilyName, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(userDisplayName) || !string.IsNullOrEmpty(context.Name)) 
                {
                    context.Identity.AddClaim(
                        new Claim(ClaimsIdentity.DefaultNameClaimType, userDisplayName ?? context.Name, XmlSchemaString, Options.AuthenticationType));
                }

                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        protected async override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return;
            }

            AuthenticationResponseChallenge challenge = 
                Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                var beforeRedirectContext = new AzureADBeforeRedirectContext(Context, Options);
                Options.Provider.BeforeRedirect(beforeRedirectContext);

                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri +
                    Options.CallbackPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                var body = new List<KeyValuePair<string, string>>();
                body.Add(new KeyValuePair<string, string>("response_type", "code"));
                body.Add(new KeyValuePair<string, string>("client_id", Options.ClientId));
                body.Add(new KeyValuePair<string, string>("redirect_uri", redirectUri));

                // AzureAD requires a specific resource to be used as the token audience
                if (String.IsNullOrEmpty(Options.Resource)) Options.Resource = UserInfoResource;

                AddToQueryString(body, properties, "resource", Options.Resource);
                AddToQueryString(body, properties, "prompt");
                AddToQueryString(body, properties, "login_hint");
                AddToQueryString(body, properties, "domain_hint");
                // Microsoft-specific parameter
                // msafed=0 forces the interpretation of login_hint as an organizational accoount
                // and does not present to user the Work vs. Personal account picker
                AddToQueryString(body, properties, "msafed");

                string state = Options.StateDataFormat.Protect(properties);
                body.Add(new KeyValuePair<string, string>("state", state));
                body.Add(new KeyValuePair<string, string>("nonce", state));

                var queryString = await new FormUrlEncodedContent(body).ReadAsStringAsync();
                string authorizationEndpoint = $"{String.Format(AuthorizeEndpointFormat, Options.Tenant)}?{queryString}";

                if (Options.RequestLogging) 
                {
                    _logger.WriteVerbose(String.Format("GET {0}", authorizationEndpoint));
                }

                var redirectContext = 
                    new AzureADApplyRedirectContext(Context, Options, properties, authorizationEndpoint);
                Options.Provider.ApplyRedirect(redirectContext);
            }

            return;
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                // TODO: error responses

                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new AzureADReturnEndpointContext(Context, ticket);
                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null && context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(
                            grantIdentity.Claims, 
                            context.SignInAsAuthenticationType, 
                            grantIdentity.NameClaimType, 
                            grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "internal");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }
        #endregion


        private async Task<string> GetUserInfoAccessToken(string authorizationCode) 
        {
            string requestPrefix = Request.Scheme + "://" + Request.Host;
            string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

            // Build up the body for the token request
            var body = new List<KeyValuePair<string, string>>();
            body.Add(new KeyValuePair<string, string>("grant_type", "authorization_code"));
            body.Add(new KeyValuePair<string, string>("code", authorizationCode));
            body.Add(new KeyValuePair<string, string>("redirect_uri", redirectUri));
            body.Add(new KeyValuePair<string, string>("client_id", Options.ClientId));
            body.Add(new KeyValuePair<string, string>("client_secret", Options.ClientSecret));
            body.Add(new KeyValuePair<string, string>("resource", UserInfoResource));

            // Request the token
            var httpRequest =
                    new HttpRequestMessage(HttpMethod.Post, String.Format(TokenEndpointFormat, Options.Tenant));
            httpRequest.Content = new FormUrlEncodedContent(body);
            if (Options.RequestLogging) {
                _logger.WriteInformation(httpRequest.ToLogString());
            }
            var httpResponse = await _httpClient.SendAsync(httpRequest);
            string content = await httpResponse.Content.ReadAsStringAsync();
            if (Options.ResponseLogging) {
                // Note: avoid using one of the Write* methods that takes a format string as input
                // because the curly brackets from a JSON response will be interpreted as
                // curly brackets for the format string and function will throw a FormatException
                _logger.WriteInformation(httpResponse.ToLogString());
            }
            // Deserializes the token response
            var tokenResponse = JsonConvert.DeserializeObject<JObject>(content);
            string accessToken = tokenResponse["access_token"].Value<string>();

            return accessToken;
        }


        private async Task<JObject> GetUserInfoAsync(string accessToken) 
        {
            var userRequest = new HttpRequestMessage(HttpMethod.Get, UserInfoEndpoint);
            userRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            var userResponse = await _httpClient.SendAsync(userRequest);
            var userContent = await userResponse.Content.ReadAsStringAsync();
            if (!userResponse.IsSuccessStatusCode) 
            {
                return null;
            }

            return JObject.Parse(userContent);
        }


        private static void AddToQueryString(
            List<KeyValuePair<string, string>> queryString, 
            AuthenticationProperties properties, 
            string name, string defaultValue = null) 
        {
            string value;
            if (!properties.Dictionary.TryGetValue(name, out value)) 
            {
                value = defaultValue;
            }
            else 
            {
                // Remove the parameter from AuthenticationProperties so it won't be serialized to state parameter
                properties.Dictionary.Remove(name);
            }

            if (value == null) 
            {
                return;
            }

            queryString.Add(new KeyValuePair<string, string>(name, value));
        }
    }
}