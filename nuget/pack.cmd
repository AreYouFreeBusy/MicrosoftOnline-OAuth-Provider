msbuild /property:Configuration=Release ..\AzureAD-OAuth-Provider\AzureAD-OAuth-Provider.csproj
msbuild /property:Configuration=Release ..\MicrosoftOnline-OAuth-Provider\MicrosoftOnline-OAuth-Provider.csproj
nuget pack AzureAD-OAuth-Provider.nuspec