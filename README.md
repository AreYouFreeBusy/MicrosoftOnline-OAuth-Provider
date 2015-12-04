MicrosoftOnline-OAuth-Provider
======================

MicrosoftOnline is the unified OAuth and OpenID provider for both Azure AD (aka Microsoft work/school) accounts used with Office 365 and Microsoft Accounts (aka Microsoft personal) accounts used with Outlook.com.

Owin.Security.Providers.MicrosoftOnline provider supercedes both Owin.Security.Providers.AzureAD provider (which is a part of this repository) and Microsoft.Owin.Security.MicrosoftAccount provider (which is part of the Katana project).

ASP.NET MVC 5 Web apps that use ASP.NET Identity 2.0 with OWIN as described at http://www.asp.net/identity can integrate with Office 365 and Outlook.com REST APIs using this middleware authentication provider (either for your tenant or multi-tenant). 

This library was originally developed for and is in use at https://freebusy.io

This library is available as a NuGet package at https://www.nuget.org/packages/Owin.Security.Providers.AzureAD/

How to Use
======================
See an example of how to configure your ASP.NET web app at https://github.com/AreYouFreeBusy/MicrosoftOnline-OAuth-Provider/blob/master/Sample/App_Start/Startup.Auth.cs