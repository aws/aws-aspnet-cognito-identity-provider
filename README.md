![.NET on AWS Banner](./logo.png ".NET on AWS")

## ASP.NET Core Identity Provider for Amazon Cognito

[![nuget](https://img.shields.io/nuget/v/Amazon.AspNetCore.Identity.Cognito.svg)](https://www.nuget.org/packages/Amazon.AspNetCore.Identity.Cognito/)

ASP.NET Core Identity Provider for [Amazon Cognito](https://aws.amazon.com/cognito/) simplifies using [Amazon Cognito](https://aws.amazon.com/cognito/) as a membership storage solution for building ASP.NET Core web applications using [ASP.NET Core Identity](https://github.com/aspnet/Identity/).

This library is not compatible with older versions of Identity such as the ones for ASP.NET MVC5 and lower. It only supports ASP.NET Core Identity and targets the .NET Standard 2.0.

The library introduces the following dependencies:

* [Amazon.Extensions.CognitoAuthentication](https://www.nuget.org/packages/Amazon.Extensions.CognitoAuthentication/)
* [AWSSDK.CognitoIdentity](https://www.nuget.org/packages/AWSSDK.CognitoIdentity/)
* [AWSSDK.CognitoIdentityProvider](https://www.nuget.org/packages/AWSSDK.CognitoIdentityProvider/)
* [AWSSDK.Extensions.NETCore.Setup](https://www.nuget.org/packages/AWSSDK.Extensions.NETCore.Setup/)
* [Microsoft.AspNetCore.Identity](https://www.nuget.org/packages/Microsoft.AspNetCore.Identity/)
* [Microsoft.Extensions.Configuration](https://www.nuget.org/packages/Microsoft.Extensions.Configuration/)
* [Microsoft.Extensions.DependencyInjection](https://www.nuget.org/packages/Microsoft.Extensions.DependencyInjection/)


# Getting Started

Follow the examples below to see how the library can be integrated into your web application.  

This library extends the ASP.NET Core Identity membership system by using Amazon Cognito as a [Custom Storage Provider for ASP.NET Identity](https://docs.microsoft.com/en-us/aspnet/identity/overview/extensibility/overview-of-custom-storage-providers-for-aspnet-identity).

## Referencing the library

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

Next the user pool and user pool client need to be configured as part of the IConfiguration of the ASP.NET Core application. For a development user pool edit either the `appsettings.Development.json` file or the projects [secrets.json](https://docs.microsoft.com/en-us/aspnet/core/security/app-secrets) file. Below is an example of the JSON snippet to go into the file.

```csharp
"AWS": {
    "Region": "<your region id goes here>",
    "UserPoolClientId": "<your user pool client id goes here>",
    "UserPoolClientSecret": "<your user pool client secret goes here>",
    "UserPoolId": "<your user pool id goes here>"
}
```

**Note:** If using `appsettings.Development.json` or some other file in your project structure be careful checking in secrets to source control.

For a production user pool it is recommend to configure the same settings as above either through IConfiguration's [environment variable support](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/configuration/#environment-variables) or with the AWS System Manager's parameter store which can be integrated with IConfiguration using the [Amazon.Extensions.Configuration.SystemsManager](https://aws.amazon.com/blogs/developer/net-core-configuration-provider-for-aws-systems-manager/) NuGet package.


Alternatively, instead of relying on a configuration file, you can inject your own instances of IAmazonCognitoIdentityProvider and CognitoUserPool in your Startup.cs file.

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

In addition, this library introduces two child classes of SigninManager and UserManager designed for Amazon Cognito authentication and user management workflow: CognitoSigninManager and CognitoUserManager classes.

These two classes expose additional methods designed to support Amazon Cognito features, such as sending validation data to pre-signup [AWS Lambda triggers](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-sign-up.html) when registering a new user:

```csharp
/// <summary>
/// Creates the specified <paramref name="user"/> in Cognito with the given password and validation data,
/// as an asynchronous operation.
/// </summary>
/// <param name="user">The user to create.</param>
/// <param name="password">The password for the user</param>
/// <param name="validationData">The validation data to be sent to the pre sign-up lambda triggers.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
public async Task<IdentityResult> CreateAsync(TUser user, string password, IDictionary<string, string> validationData)
```

# Explore the documentation and sample application

Feel free to explore the [documentation folder](https://github.com/aws/aws-aspnet-cognito-identity-provider/tree/master/docs) and the [sample application](https://github.com/aws/aws-aspnet-cognito-identity-provider/tree/master/samples). These two resources provide additionnal examples on how to use the library with your ASP.NET Core web application.

# Getting Help

We use the [GitHub issues](https://github.com/aws/aws-aspnet-cognito-identity-provider/issues) for tracking bugs and feature requests and have limited bandwidth to address them.

If you think you may have found a bug, please open an [issue](https://github.com/aws/aws-aspnet-cognito-identity-provider/issues/new)

# Contributing

We welcome community contributions and pull requests. See
[CONTRIBUTING](./CONTRIBUTING.md) for information on how to set up a development
environment and submit code.

# Additional Resources

[AWS .NET GitHub Home Page](https://github.com/aws/dotnet)  
GitHub home for .NET development on AWS. You'll find libraries, tools, and resources to help you build .NET applications and services on AWS.

[AWS Developer Center - Explore .NET on AWS](https://aws.amazon.com/developer/language/net/)  
Find all the .NET code samples, step-by-step guides, videos, blog content, tools, and information about live events that you need in one place. 

[AWS Developer Blog - .NET](https://aws.amazon.com/blogs/developer/category/programing-language/dot-net/)  
Come see what .NET developers at AWS are up to!  Learn about new .NET software announcements, guides, and how-to's.

[@dotnetonaws](https://twitter.com/dotnetonaws)  
Follow us on twitter!

# License

Libraries in this repository are licensed under the Apache 2.0 License. 

See [LICENSE](./LICENSE) and [NOTICE](./NOTICE) for more information.
