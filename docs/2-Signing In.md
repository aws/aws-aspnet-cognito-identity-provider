![.NET on AWS Banner](./../logo.png ".NET on AWS")

# Authentication using the ASP.NET Core Identity Provider for Amazon Cognito


## Signing in using the CognitoSigninManager


You can use any of the following methods of the CognitoSigninManager to sign in:


```csharp

/// <summary>
/// Attempts to sign in the specified <paramref name="user"/> and <paramref name="password"/> combination
/// as an asynchronous operation.
/// </summary>
/// <param name="user">The user to sign in.</param>
/// <param name="password">The password to attempt to sign in with.</param>
/// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
/// <param name="lockoutOnFailure">Flag indicating if the user account should be locked if the sign in fails.</param>
/// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
/// for the sign-in attempt.</returns>
Task<SignInResult> PasswordSignInAsync(TUser user, string password, bool isPersistent, bool lockoutOnFailure);

/// <summary>
/// Attempts to sign in the specified <paramref name="userName"/> and <paramref name="password"/> combination
/// as an asynchronous operation.
/// </summary>
/// <param name="userName">The user name to sign in.</param>
/// <param name="password">The password to attempt to sign in with.</param>
/// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
/// <param name="lockoutOnFailure">Flag indicating if the user account should be locked if the sign in fails.</param>
/// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
/// for the sign-in attempt.</returns>
Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure);
```

## The [CognitoSigninResult](https://github.com/aws/aws-aspnet-cognito-identity-provider/blob/master/src/Amazon.AspNetCore.Identity.Cognito/CognitoSignInResult.cs) class


The CognitoSigninResult class extends the [SigninResult](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.identity.signinresult?view=aspnetcore-2.2) class, which is the output of the PasswordSignInAsync methods. It can have the following values:

* Failed: a SignInResult that represents a failed sign-in.
* Succeeded: The authentication was successful.
* NotAllowed: The user is not allowed to sign-in
* RequiresTwoFactor: The response to a two factor authentication challenge is required to proceed with the authentication process.
* RequiresPasswordChange: The password of the user needs to be changed.
* RequiresPasswordReset: The password of the user needs to be reset.

You can find an example of the login workflow [in the sample application.](https://github.com/aws/aws-aspnet-cognito-identity-provider/blob/master/samples/Samples/Areas/Identity/Pages/Account/Login.cshtml.cs#L68)


## Responding to a two factor authentication challenge

If presented with a CognitoSigninResult.RequiresTwoFactor result after calling PasswordSignInAsync(), you can reply to the challenge using the following methods of the CognitoSigninManager:


```csharp
/// <summary>
/// Gets the <typeparamref name="TUser"/> for the current two factor authentication login, as an asynchronous operation.
/// </summary>
/// <returns>The task object representing the asynchronous operation containing the <typeparamref name="TUser"/>
/// for the sign-in attempt.</returns>
Task<TUser> GetTwoFactorAuthenticationUserAsync();

/// <summary>
/// Validates the two factor sign in code and creates and signs in the user, as an asynchronous operation.
/// </summary>
/// <param name="code">The two factor authentication code to validate.</param>
/// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
/// <param name="rememberClient">Flag indicating whether the current browser should be remember, suppressing all further 
/// two factor authentication prompts.</param>
/// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
/// for the sign-in attempt.</returns>
Task<SignInResult> RespondToTwoFactorChallengeAsync(string code, bool isPersistent, bool rememberClient);
```

You can find an example of this workflow in the [sample web application.](https://github.com/aws/aws-aspnet-cognito-identity-provider/blob/master/samples/Samples/Areas/Identity/Pages/Account/LoginWith2fa.cshtml.cs#L61)