![.NET on AWS Banner](./../logo.png ".NET on AWS")

# Users management using the ASP.NET Core Identity Provider for Amazon Cognito

## Retrieve a CognitoUser phone number or email

In addition to the attributes property of the CognitoUserClass, the CognitoUserManager class exposes the following methods to retrieve a CognitoUser phone number or email:

```csharp
/// <summary>
/// Gets the telephone number, if any, for the specified <paramref name="user"/>.
/// </summary>
/// <param name="user">The user whose telephone number should be retrieved.</param>
/// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the user's telephone number, if any.</returns>
Task<string> GetPhoneNumberAsync(TUser user);

/// <summary>
/// Gets the email address for the specified <paramref name="user"/>.
/// </summary>
/// <param name="user">The user whose email should be returned.</param>
/// <returns>The task object containing the results of the asynchronous operation, the email address for the specified <paramref name="user"/>.</returns>
Task<string> GetEmailAsync(TUser user);
```

## Update a CognitoUser phone number or email

The CognitoUserManager class exposes the following methods to update a CognitoUser phone number or email:

```csharp
/// <summary>
/// Sets the phone number for the specified <paramref name="user"/>.
/// </summary>
/// <param name="user">The user whose phone number to set.</param>
/// <param name="phoneNumber">The phone number to set.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> SetPhoneNumberAsync(TUser user, string phoneNumber);

/// <summary>
/// Sets the <paramref name="email"/> address for a <paramref name="user"/>.
/// </summary>
/// <param name="user">The user whose email should be set.</param>
/// <param name="email">The email to set.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> SetEmailAsync(TUser user, string email);
```

## Resend the email or phone number confirmation token

The CognitoUserManager class exposes the following methods to resend the email or phone number confirmation token to the CognitoUser:

```csharp
/// <summary>
/// Generates and sends an email confirmation token for the specified user.
/// </summary>
/// <param name="user">The user to generate and send an email confirmation token for.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> SendEmailConfirmationTokenAsync(TUser user);

/// <summary>
/// Generates and sends a phone confirmation token for the specified user.
/// </summary>
/// <param name="user">The user to generate and send a phone confirmation token for.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> SendPhoneConfirmationTokenAsync(TUser user);
```

If the output result is successful, a confirmation token would have been sent to the CognitoUser either via email or phone.


## Verify an email or phone number using the confirmation token

The CognitoUserManager class exposes the following methods to verify an email or phone number using the confirmation token for a specified CognitoUser:

```csharp
/// <summary>
/// Confirms the email of an user by validating that an email confirmation token is valid for the specified <paramref name="user"/>.
/// This operation requires a logged in user.
/// </summary>
/// <param name="user">The user to validate the token against.</param>
/// <param name="confirmationCode">The email confirmation code to validate.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> ConfirmEmailAsync(TUser user, string confirmationCode);

/// <summary>
/// Confirms the phone number of an user by validating that an email confirmation token is valid for the specified <paramref name="user"/>.
/// This operation requires a logged in user.
/// </summary>
/// <param name="user">The user to validate the token against.</param>
/// <param name="confirmationCode">The phone number confirmation code to validate.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> ConfirmPhoneNumberAsync(TUser user, string confirmationCode);
```
