using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(AzureAD_OAuth_Demo.Startup))]
namespace AzureAD_OAuth_Demo
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
