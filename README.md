![.NET on AWS Banner](./logo.png ".NET on AWS")

## ASP.NET Core Identity Provider for Amazon Cognito

**This software is in development and we do not recommend using this software in production environment.**

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

## Building the library
While this library is in development, you will need to build it and manually reference it in your ASP.NET Core web application.

Change your ASP.Net Core web application csproj to include the following line:

```csharp
<ProjectReference Include="..\..\..\aws-aspnet-cognito-identity-provider\src\Amazon.AspNetCore.Identity.AWSCognito\Amazon.AspNetCore.Identity.AWSCognito.csproj" />
```

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

Alternatively, instead of using the appsettings.json you can directly inject your own instances of Amazon Cognito service and user pool clients to be used when calling AddCognitoIdentity():

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

Once Amazon Cognito is added as the default ASP.NET Core Identity Provider, you will need to make changes to your code to use the newly introduced CognitoUser class instead of the default ApplicationUser class.

These changes will be required in existing RaZor views and controllers. Here is an example with a RaZor view:

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

[@awsfornet](https://twitter.com/awsfornet)  
Follow us on twitter!

# License

Libraries in this repository are licensed under the Apache 2.0 License. 

See [LICENSE](./LICENSE) and [NOTICE](./NOTICE) for more information.