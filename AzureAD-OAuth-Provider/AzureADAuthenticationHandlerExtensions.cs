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
    public static class AzureADAuthenticationHandlerExtensions 
    {
        /// <summary>
        /// 
        /// </summary>
        public static string ToLogString(this HttpRequestMessage httpRequest) 
        {
            var serializedRequest = AsyncHelpers.RunSync<byte[]>(() =>
                new HttpMessageContent(httpRequest).ReadAsByteArrayAsync());
            return System.Text.Encoding.UTF8.GetString(serializedRequest);
        }


        /// <summary>
        /// 
        /// </summary>
        public static string ToLogString(this HttpResponseMessage httpResponse) 
        {
            var serializedRequest = AsyncHelpers.RunSync<byte[]>(() =>
                new HttpMessageContent(httpResponse).ReadAsByteArrayAsync());
            return System.Text.Encoding.UTF8.GetString(serializedRequest);
        } 
    }
}