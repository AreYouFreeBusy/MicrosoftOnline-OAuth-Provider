AzureAD-OAuth-Provider
======================

Azure AD is used by Office 365 tenants and supports authentication and authorization using OAuth2. 

ASP.NET MVC 5 Web apps that use ASP.NET Identity 2.0 with OWIN as described at 
http://www.asp.net/identity you can integrate with Office 365 REST APIs 
http://msdn.microsoft.com/en-us/office/office365/api/api-catalog 
using this middleware authentication provider (either for your tenant or multi-tenant). 

This library was originally developed for and is in use at https://freebusy.io

This library is available as a NuGet package at https://www.nuget.org/packages/Owin.Security.Providers.AzureAD/

How to Use
======================
See an example of how to configure your ASP.NET web app at https://github.com/AreYouFreeBusy/AzureAD-OAuth-Provider/blob/master/AzureAD-OAuth-Demo/App_Start/Startup.Auth.cs