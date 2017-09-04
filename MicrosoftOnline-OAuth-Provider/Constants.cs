//  Copyright 2015 Stefan Negritoiu. See LICENSE file for more information.

namespace Owin.Security.Providers.MicrosoftOnline
{
    internal static class Constants
    {
        public const string DefaultAuthenticationType = "MicrosoftOnline";
    }

    public static class MicrosoftAccountType
    {
        public const string All = "common";
        public const string WorkSchool = "organizations";
        public const string Personal = "consumers";
    }
}