![.NET on AWS Banner](./../logo.png ".NET on AWS")

# User Password management using the ASP.NET Core Identity Provider for Amazon Cognito

## Change a CognitoUser password

The CognitoUserManager class exposes the following method to change a CognitoUser user password:

```csharp
/// <summary>
/// Changes a user's password after confirming the specified <paramref name="currentPassword"/> is correct,
/// as an asynchronous operation.
/// </summary>
/// <param name="user">The user whose password should be set.</param>
/// <param name="currentPassword">The current password to validate before changing.</param>
/// <param name="newPassword">The new password to set for the specified <paramref name="user"/>.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> ChangePasswordAsync(TUser user, string currentPassword, string newPassword);
```
You can find examples on how to change a user password in the [sample web application.](https://github.com/aws/aws-aspnet-cognito-identity-provider/blob/master/samples/Samples/Areas/Identity/Pages/Account/ChangePassword.cshtml.cs#L75)


## Check if a CognitoUser password needs to be changed

The CognitoUserManager class exposes the following method to check if a user password needs to be changed:

```csharp
/// <summary>
/// Checks if the password needs to be changed for the specified <paramref name="user"/>.
/// </summary>
/// <param name="user">The user to check if the password needs to be changed.</param>
/// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if the password needs to be changed, false otherwise.</returns>
Task<bool> IsPasswordChangeRequiredAsync(TUser user);
```

## Check if a CognitoUser password needs to be reset

The CognitoUserManager class exposes the following method to check if a user password needs to be reset:

```csharp
/// <summary>
/// Checks if the password needs to be reset for the specified <paramref name="user"/>.
/// </summary>
/// <param name="user">The user to check if the password needs to be reset.</param>
/// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if the password needs to be reset, false otherwise.</returns>
Task<bool> IsPasswordResetRequiredAsync(TUser user);
```

## Send a confirmation token to a CognitoUser to reset its password

The CognitoUserManager class exposes the following methods to send a confirmation token to a CognitoUser to reset its password:

```csharp
/// <summary>
/// Resets the <paramref name="user"/>'s password and sends the confirmation token to the user 
/// via email or sms depending on the user pool policy.
/// </summary>
/// <param name="user">The user whose password should be reset.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> ResetPasswordAsync(TUser user);
```

## Reset a CognitoUser password using the confirmation token received by sms or email

The CognitoUserManager class exposes the following methods to reset a CognitoUser password using the confirmation token received by sms or email:

```csharp
/// <summary>
/// Resets the <paramref name="user"/>'s password to the specified <paramref name="newPassword"/> after
/// validating the given password reset <paramref name="token"/>.
/// </summary>
/// <param name="user">The user whose password should be reset.</param>
/// <param name="token">The password reset token to verify.</param>
/// <param name="newPassword">The new password to set if reset token verification succeeds.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> ResetPasswordAsync(TUser user, string token, string newPassword);
```

