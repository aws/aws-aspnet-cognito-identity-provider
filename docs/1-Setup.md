![.NET on AWS Banner](./../logo.png ".NET on AWS")

## ASP.NET Core Identity Provider for Amazon Cognito

## Getting familiar with the AWS SDK for .NET and the AWS Toolkit for Visual Studio

This library is built on top of the AWS SDK for .NET to communicate with Amazon Cognito. We recommend installing the [AWS Toolkit for Visual Studio](https://docs.aws.amazon.com/toolkit-for-visual-studio/latest/user-guide/setup.html) and creating a default profile to manage your Access Keys and Secret Keys.

You can find more information on the AWS SDK for .NET on the [AWS Guide for .NET Developers](https://docs.aws.amazon.com/sdk-for-net/v3/ndg/welcome.html).

## Try-out the sample web application

You can *quickly try the library out* by cloning and exploring the [sample web application from the GitHub repository](https://github.com/aws/aws-aspnet-cognito-identity-provider/tree/master/samples).

Just make the necessary changes to the following properties to the *appsettings.json* file to use the web application with your Cognito User Pool:

```csharp
"AWS": {
    "Region": "<your region id goes here>",
    "UserPoolClientId": "<your user pool client id goes here>",
    "UserPoolClientSecret": "<your user pool client secret goes here>",
    "UserPoolId": "<your user pool id goes here>"
}
```


## Upgrading an existing web application

Simply add the following NuGet dependencies to your ASP.NET Core application:

* [Amazon.AspNetCore.Identity.Cognito](https://www.nuget.org/packages/Amazon.AspNetCore.Identity.Cognito/)
* [Amazon.Extensions.CognitoAuthentication](https://www.nuget.org/packages/Amazon.Extensions.CognitoAuthentication/)


## Adding Amazon Cognito as an Identity Provider

To add Amazon Cognito as an Identity Provider, make the following change to your code:

Startup.cs:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    // Adds Amazon Cognito as Identity Provider
    services.AddCognitoIdentity();
    ...
}

public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    // If not already enabled, you will need to enable ASP.NET Core authentication
    app.UseAuthentication();
    ...
}
```

In order to automatically inject Cognito service and user pool clients make the following changes to your appsettings.json:

```csharp
"AWS": {
    "Region": "<your region id goes here>",
    "UserPoolClientId": "<your user pool client id goes here>",
    "UserPoolClientSecret": "<your user pool client secret goes here>",
    "UserPoolId": "<your user pool id goes here>"
}
```

Alternatively, instead of relying on a configuration file, you can inject your own instances of IAmazonCognitoIdentityProvider and CognitoUserPool in your Startup.cs file, or use the newly announced [AWS Systems Manager to store your web application parameters](https://aws.amazon.com/blogs/developer/net-core-configuration-provider-for-aws-systems-manager/).

```csharp
public void ConfigureServices(IServiceCollection services)
{
    ...
    // Adds your own instance of Amazon Cognito clients 
    // cognitoIdentityProvider and cognitoUserPool are variables you would have instanciated yourself
    services.AddSingleton<IAmazonCognitoIdentityProvider>(cognitoIdentityProvider);
    services.AddSingleton<CognitoUserPool>(cognitoUserPool);

    // Adds Amazon Cognito as Identity Provider
    services.AddCognitoIdentity();
    ...
}
```

## Using the CognitoUser class as your web application user class

Once Amazon Cognito is added as the default ASP.NET Core Identity Provider, you need to use the newly introduced CognitoUser class instead of the default ApplicationUser class.

These changes will be required in existing Razor views and controllers. Here is an example with a Razor view:

```csharp
@using Microsoft.AspNetCore.Identity
@using Amazon.Extensions.CognitoAuthentication

@inject SignInManager<CognitoUser> SignInManager
@inject UserManager<CognitoUser> UserManager
```