//  Copyright 2015 Stefan Negritoiu. See LICENSE file for more information.

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

namespace Owin.Security.Providers.MicrosoftOnline
{
    public class MicrosoftOnlineAuthenticationHandler : AuthenticationHandler<MicrosoftOnlineAuthenticationOptions>
    {
        // for endpoint docs see
        // https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols
        // https://docs.microsoft.com/en-us/azure/active-directory/develop/authentication-national-cloud
        // https://docs.microsoft.com/en-us/azure/azure-government/documentation-government-developer-guide#endpoint-mapping
        // https://docs.microsoft.com/en-us/graph/deployments

        private const string AuthHost_China =            "https://login.chinacloudapi.cn";
        private const string AuthHost_Commercial =       "https://login.microsoftonline.com";
        private const string AuthHost_Germany =          "https://login.microsoftonline.de";
        private const string AuthHost_USGovernment =     "https://login.microsoftonline.com";
        private const string AuthHost_USGovernmentHigh = "https://login.microsoftonline.us";
        private const string AuthHost_USGovernmentDoD =  "https://login.microsoftonline.us";

        private const string GraphHost_China =            "https://microsoftgraph.chinacloudapi.cn";
        private const string GraphHost_Commercial =       "https://graph.microsoft.com";
        private const string GraphHost_Germany =          "https://graph.microsoft.de";
        private const string GraphHost_USGovernment =     "https://graph.microsoft.com";
        private const string GraphHost_USGovernmentHigh = "https://graph.microsoft.us";
        private const string GraphHost_USGovernmentDoD =  "https://dod-graph.microsoft.us";

        private const string AdminConsentEndpointFormat = "/{0}/v2.0/adminconsent";
        private const string AuthorizeEndpointFormat = "/{0}/oauth2/v2.0/authorize";
        private const string TokenEndpointFormat = "/{0}/oauth2/v2.0/token";

        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string UserInfoEndpoint = "/v1.0/me";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public MicrosoftOnlineAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;
                JObject id = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                else if (Options.ErrorLogging) 
                {
                    _logger.WriteError($"Could not find code on callback URL {Request.Uri}");
                }

                values = query.GetValues("state");
                if (values != null && values.Count == 1) 
                {
                    state = values[0];
                }
                else if (Options.ErrorLogging) 
                {
                    _logger.WriteError($"Could not find state on callback URL {Request.Uri}");
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null) 
                {
                    _logger.WriteError($"Could not decode state");
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    _logger.WriteError($"Could not validate state");
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                // Build up the body for the token request
                var body = new List<KeyValuePair<string, string>> 
                {
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri),
                    new KeyValuePair<string, string>("client_id", Options.ClientId),
                    new KeyValuePair<string, string>("client_secret", Options.ClientSecret)
                };

                // Request the token
                var httpRequest = new HttpRequestMessage(HttpMethod.Post, ComposeTokenEndpoint(properties)) 
                {
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
                JObject response = JsonConvert.DeserializeObject<JObject>(content);
                string accessToken = response.Value<string>("access_token");
                string scope = response.Value<string>("scope");
                string expires = response.Value<string>("expires_in");
                string refreshToken = response.Value<string>("refresh_token");
                string idToken = response.Value<string>("id_token");

                // id_token should be a Base64 url encoded JSON web token
                string[] segments;
                if (!String.IsNullOrEmpty(idToken) && (segments = idToken.Split('.')).Length == 3) 
                {
                    string payload = Base64UrlDecode(segments[1]);
                    if (!String.IsNullOrEmpty(payload)) id = JObject.Parse(payload);
                }

                var context = new MicrosoftOnlineAuthenticatedContext(Context, id, accessToken, scope, expires, refreshToken);
                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                if (!string.IsNullOrEmpty(context.Subject)) 
                {
                    context.Identity.AddClaim(
                        new Claim(ClaimTypes.NameIdentifier, context.Subject, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Upn)) 
                {
                    context.Identity.AddClaim(
                        new Claim(ClaimTypes.Upn, context.Upn, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Email)) 
                {
                    context.Identity.AddClaim(
                        new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
                }
                else 
                {
                    // get user email address from UserInfo endpoint
                    string userEmail = null;
                    var userRequest = new HttpRequestMessage(HttpMethod.Get, ComposeUserInfoEndpoint(properties));
                    userRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                    var userResponse = await _httpClient.SendAsync(userRequest);
                    var userContent = await userResponse.Content.ReadAsStringAsync();
                    if (userResponse.IsSuccessStatusCode) 
                    {
                        var userJson = JObject.Parse(userContent);
                        userEmail = userJson["mail"]?.Value<string>();
                    }
                    if (!string.IsNullOrEmpty(userEmail)) 
                    {
                        context.Email = userEmail;
                        context.Identity.AddClaim(
                            new Claim(ClaimTypes.Email, userEmail, XmlSchemaString, Options.AuthenticationType));
                    }
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
                if (!string.IsNullOrEmpty(context.Name)) 
                {
                    context.Identity.AddClaim(
                        new Claim(ClaimsIdentity.DefaultNameClaimType, context.Name, XmlSchemaString, Options.AuthenticationType));
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

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = 
                Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                var beforeRedirectContext = new MicrosoftOnlineBeforeRedirectContext(Context, Options);
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

                var queryStrings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) 
                {
                    { "response_type", "code" },
                    { "client_id", Options.ClientId },
                    { "redirect_uri", redirectUri }
                };
                AddQueryString(queryStrings, properties, "response_mode");
                AddQueryString(queryStrings, properties, "prompt");
                AddQueryString(queryStrings, properties, "login_hint");
                AddQueryString(queryStrings, properties, "domain_hint");

                // if AuthenticationProperties for this session specifies a scope property
                // it should take precedence over the value in AuthenticationOptions
                string scopeProperty;
                if (properties.Dictionary.TryGetValue(Constants.ScopeAuthenticationProperty, out scopeProperty) &&
                    !String.IsNullOrWhiteSpace(scopeProperty)) 
                {
                    // Assumption that scopeProperty is correctly formatted
                    AddQueryString(queryStrings, properties, "scope", scopeProperty);
                }
                else 
                {
                    AddQueryString(queryStrings, properties, "scope", String.Join(" ", Options.Scope));
                }

                string state = Options.StateDataFormat.Protect(properties);
                queryStrings.Add("state", state);

                string authorizeEndpoint = WebUtilities.AddQueryString(ComposeAuthorizeEndpoint(properties), queryStrings);
                if (Options.RequestLogging) 
                {
                    _logger.WriteVerbose(String.Format("GET {0}", authorizeEndpoint));
                }

                var redirectContext = new MicrosoftOnlineApplyRedirectContext(Context, Options, properties, authorizeEndpoint);
                Options.Provider.ApplyRedirect(redirectContext);
            }

            return Task.FromResult<object>(null);
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

                var context = new MicrosoftOnlineReturnEndpointContext(Context, ticket);
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

        private string Environment2AuthHost(string environment) 
        {
            switch (environment) 
            {
                case Environment.China:
                    return AuthHost_China;
                case Environment.Commercial:
                    return AuthHost_Commercial;
                case Environment.Germany:
                    return AuthHost_Germany;
                case Environment.USGovernment:
                    return AuthHost_USGovernment;
                case Environment.USGovernmentHigh:
                    return AuthHost_USGovernmentHigh;
                case Environment.USGovernmentDoD:
                    return AuthHost_USGovernmentDoD;
                default:
                    if (Options.ErrorLogging) 
                    {
                        _logger.WriteError($"Invalid value for {nameof(Constants.EnvironmentAuthenticationProperty)}");
                    }
                    return AuthHost_Commercial;
            }
        }

        private string Environment2GraphHost(string environment) 
        {
            switch (environment) 
            {
                case Environment.China:
                    return GraphHost_China;
                case Environment.Commercial:
                    return GraphHost_Commercial;
                case Environment.Germany:
                    return GraphHost_Germany;
                case Environment.USGovernment:
                    return GraphHost_USGovernment;
                case Environment.USGovernmentHigh:
                    return GraphHost_USGovernmentHigh;
                case Environment.USGovernmentDoD:
                    return GraphHost_USGovernmentDoD;
                default:
                    if (Options.ErrorLogging) 
                    {
                        _logger.WriteError($"Invalid value for {nameof(Constants.EnvironmentAuthenticationProperty)}");
                    }
                    return GraphHost_Commercial;
            }
        }

        private string ComposeAuthorizeEndpoint(AuthenticationProperties properties) 
        {
            string endpointPath = String.Format(AuthorizeEndpointFormat, Options.Tenant);
            bool adminConsent = Options.AdminConsent;
            
            // if AuthenticationProperties for this session specifies an admin_consent property
            // it should take precedence over the value in AuthenticationOptions
            string adminConsentProperty;
            bool adminConsentValue;
            if (properties.Dictionary.TryGetValue(Constants.AdminConsentAuthenticationProperty, out adminConsentProperty) &&
                bool.TryParse(adminConsentProperty, out adminConsentValue)) 
            {
                adminConsent = adminConsentValue;
            }
            if (adminConsent) 
            {
                endpointPath = String.Format(AdminConsentEndpointFormat, Options.Tenant);
            }

            return ComposeAuthEndpoint(properties, endpointPath);
        }

        private string ComposeTokenEndpoint(AuthenticationProperties properties) 
        {
            string endpointPath = String.Format(TokenEndpointFormat, Options.Tenant);
            return ComposeAuthEndpoint(properties, endpointPath);
        }

        private string ComposeUserInfoEndpoint(AuthenticationProperties properties) 
        {
            string endpointPath = UserInfoEndpoint;
            return ComposeGraphEndpoint(properties, endpointPath);
        }

        private string ComposeAuthEndpoint(AuthenticationProperties properties, string endpointPath) 
        {
            string endpoint = !String.IsNullOrEmpty(Options.Environment) ?
                Environment2AuthHost(Options.Environment) + endpointPath :
                AuthHost_Commercial + endpointPath;

            // if AuthenticationProperties for this session specifies an environment property
            // it should take precedence over the value in AuthenticationOptions
            string environmentProperty;
            if (properties.Dictionary.TryGetValue(Constants.EnvironmentAuthenticationProperty, out environmentProperty)) 
            {
                endpoint = Environment2AuthHost(environmentProperty) + endpointPath;
            }

            return endpoint;
        }

        private string ComposeGraphEndpoint(AuthenticationProperties properties, string endpointPath) 
        {
            string endpoint = !String.IsNullOrEmpty(Options.Environment) ?
                Environment2GraphHost(Options.Environment) + endpointPath :
                GraphHost_Commercial + endpointPath;

            // if AuthenticationProperties for this session specifies an environment property
            // it should take precedence over the value in AuthenticationOptions
            string environmentProperty;
            if (properties.Dictionary.TryGetValue(Constants.EnvironmentAuthenticationProperty, out environmentProperty)) 
            {
                endpoint = Environment2GraphHost(environmentProperty) + endpointPath;
            }

            return endpoint;
        }

        private static void AddQueryString(IDictionary<string, string> queryStrings, AuthenticationProperties properties,
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

            queryStrings[name] = value;
        }

        /// <summary>
        /// Based on http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-08#appendix-C
        /// </summary>
        static string Base64UrlDecode(string arg) 
        {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default: throw new Exception("Illegal base64url string");
            }

            try 
            {
                System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();                
                return encoding.GetString(Convert.FromBase64String(s)); // Standard base64 decoder
            }
            catch (FormatException) 
            {
                return null;
            }
        }
    }


    public static class MicrosoftOnlineAuthenticationHandlerExtensions 
    {
        /// <summary>
        /// 
        /// </summary>
        public static string ToLogString(this HttpRequestMessage httpRequest) 
        {
            var serializedRequest = AsyncHelpers.RunSync(() => new HttpMessageContent(httpRequest).ReadAsByteArrayAsync());
            return System.Text.Encoding.UTF8.GetString(serializedRequest);
        }


        /// <summary>
        /// 
        /// </summary>
        public static string ToLogString(this HttpResponseMessage httpResponse) 
        {
            var serializedRequest = AsyncHelpers.RunSync(() => new HttpMessageContent(httpResponse).ReadAsByteArrayAsync());
            return System.Text.Encoding.UTF8.GetString(serializedRequest);
        } 
    }
}