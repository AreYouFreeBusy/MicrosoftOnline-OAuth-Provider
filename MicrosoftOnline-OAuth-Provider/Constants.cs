//  Copyright 2015 Stefan Negritoiu. See LICENSE file for more information.

namespace Owin.Security.Providers.MicrosoftOnline
{
    public static class Constants
    {
        public const string DefaultAuthenticationType = "MicrosoftOnline";

        public const string AdminConsentAuthenticationProperty = "admin_consent";
        public const string EnvironmentAuthenticationProperty = "Environment";
        public const string ScopeAuthenticationProperty = "Scope";
    }

    public static class Environment
    {
        public const string China = "China";
        public const string Commercial = "Commercial";
        public const string Germany = "Germany";
        public const string USGovernment = "USGovernment";
        public const string USGovernmentHigh = "USGovernmentHigh";
        public const string USGovernmentDoD = "USGovernmentDoD";
    }

    public static class MicrosoftAccountType
    {
        public const string All = "common";
        public const string WorkSchool = "organizations";
        public const string Personal = "consumers";
    }
}