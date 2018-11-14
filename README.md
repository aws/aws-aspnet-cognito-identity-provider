![.NET on AWS Banner](./logo.png ".NET on AWS")

## ASP.NET Core Identity Provider for AWS Cognito

This software is in development and we do not recommend using this software in production environment.

ASP.NET Core Identity Provider for [AWS Cognito](https://aws.amazon.com/cognito/) simplifies using [AWS Cognito](https://aws.amazon.com/cognito/) as a membership storage solution for building ASP.NET Core web applications using [ASP.NET Core Identity](https://github.com/aspnet/Identity/).  


The library introduces the following dependencies:

* [Amazon.Extensions.CognitoAuthentication](https://github.com/aws/aws-sdk-net-extensions-cognito)
* [AWSSDK.CognitoIdentity](https://www.nuget.org/packages/AWSSDK.CognitoIdentity/)
* [AWSSDK.CognitoIdentityProvider](https://www.nuget.org/packages/AWSSDK.CognitoIdentityProvider/)
* [AWSSDK.Extensions.NETCore.Setup](https://www.nuget.org/packages/AWSSDK.Extensions.NETCore.Setup/)
* [Microsoft.AspNetCore.Identity](https://www.nuget.org/packages/Microsoft.AspNetCore.Identity/)
* [Microsoft.Extensions.Configuration](https://www.nuget.org/packages/Microsoft.Extensions.Configuration/)
* [Microsoft.Extensions.DependencyInjection](https://www.nuget.org/packages/Microsoft.Extensions.DependencyInjection/)


# Getting Started

Follow the examples below to see how the library can be integrated into your web application.  

This library extends the ASP.NET Core Identity membership system by using AWS Cognito as a [Custom Storage Provider for ASP.NET Identity](https://docs.microsoft.com/en-us/aspnet/identity/overview/extensibility/overview-of-custom-storage-providers-for-aspnet-identity).

## Building the library
While this library is in development, you will need to build it manually, along with the following dependency:

* [Amazon.Extensions.CognitoAuthentication](https://github.com/aws/aws-sdk-net-extensions-cognito)

You can do this by running the following command on their respective source code repositories:

```csharp
dotnet pack
```

## Instructions

To add AWS Cognito as an Identity Provider, make the following change to your code:

Startup.cs:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    // Adds AWS Cognito as Identity Provider
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

Alternatively, instead of using the appsettings.json you can directly inject your own instances of AWS Cognito service and user pool clients to be used when calling AddCognitoIdentity():

```csharp
public void ConfigureServices(IServiceCollection services)
{
    ...
    // Adds your own instance of AWS Cognito clients 
    // cognitoIdentityProvider and cognitoUserPool are variables you would have instanciated yourself
    services.AddSingleton<IAmazonCognitoIdentityProvider>(cognitoIdentityProvider);
    services.AddSingleton<CognitoUserPool>(cognitoUserPool);

    // Adds AWS Cognito as Identity Provider
    services.AddCognitoIdentity();
    ...
}
```


# Getting Help

You can use the following community resources to get help. We use the [GitHub issues](https://github.com/aws/aws-aspnet-cognito-identity-provider/issues) for tracking bugs and feature requests and have limited bandwidth to address them.

* Ask a question on [StackOverflow](http://stackoverflow.com/) and tag it with `aws` and `.net`
* Come join the AWS .NET community chat on [gitter](https://gitter.im/aws/aws-sdk-net)
* Open a support ticket with [AWS Support](https://console.aws.amazon.com/support/home)
* If it turns out that you may have found a bug, please open an [issue](https://github.com/aws/aws-aspnet-cognito-identity-provider/issues/new)

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