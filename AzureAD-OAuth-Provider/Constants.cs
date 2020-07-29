//  Copyright 2014 Stefan Negritoiu. See LICENSE file for more information.

namespace Owin.Security.Providers.AzureAD
{
    public static class Constants
    {
        public const string DefaultAuthenticationType = "AzureAD";

        public const string TenantAuthenticationProperty = "Tenant";
    }

    public static class MicrosoftAccountType
    {
        public const string All = "common";
        public const string WorkSchool = "organizations";
        public const string Personal = "consumers";
    }
}