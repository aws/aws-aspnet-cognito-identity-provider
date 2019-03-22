![.NET on AWS Banner](./../logo.png ".NET on AWS")

# Users management using the ASP.NET Core Identity Provider for Amazon Cognito


## Get all CognitoUser or a subset of CognitoUser from the pool

The CognitoUserManager class exposes the following method to filter users in the pool:

```csharp
/// <summary>
/// Queries Cognito and returns the users in the pool. Optional filters can be applied on the users to retrieve based on their attributes.
/// Providing an empty attributeFilterName parameter returns all the users in the pool.
/// </summary>
/// <param name="filterAttribute"> The attribute name to filter your search on</param>
/// <param name="filterType"> The type of filter to apply (exact match or starts with)</param>
/// <param name="filterValue"> The filter value for the specified attribute.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing a IEnumerable of CognitoUser.
/// </returns>
Task<IEnumerable<CognitoUser>> GetUsersAsync(CognitoAttribute filterAttribute = null, CognitoAttributeFilterType filterType = null, string filterValue = "");
```

## Find a CognitoUser by name, email or id

The CognitoUserManager class exposes the following methods to retrieve a user in the pool:

```csharp
/// <summary>
/// Gets the user, if any, associated with the normalized value of the specified email address.
/// </summary>
/// <param name="email">The email address to return the user for.</param>
/// <returns>
/// The task object containing the results of the asynchronous lookup operation, the user, if any, associated with a normalized value of the specified email address.
/// </returns>
Task<TUser> FindByEmailAsync(string email);

/// <summary>
/// Finds and returns a user, if any, who has the specified <paramref name="userId"/>.
/// </summary>
/// <param name="userId">The user ID to search for.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userId"/> if it exists.
/// </returns>
Task<TUser> FindByIdAsync(string userId);

/// <summary>
/// Finds and returns a user, if any, who has the specified user name.
/// </summary>
/// <param name="userName">The user name to search for.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userName"/> if it exists.
/// </returns>
Task<TUser> FindByNameAsync(string userName);
```

## Create a new CognitoUser

You will first need to request a new CognitoUser object instance from the CognitoUserPool class using one of the following methods:

```csharp
/// <summary>
/// Gets a CognitoUser with the corresponding userID
/// </summary>
/// <param name="userID">The userID of the corresponding user</param>
/// <returns>Returns a CognitoUser with the corresponding userID</returns>
CognitoUser GetUser(string userID);

/// <summary>
/// Gets a CognitoUser with the corresponding userID, status and attributes
/// </summary>
/// <param name="userID">The userID of the corresponding user</param>
/// <param name="status">The status of the corresponding user</param>
/// <param name="attributes">The attributes of the corresponding user</param>
/// <returns>Returns a CognitoUser with the corresponding userID</returns>
CognitoUser GetUser(string userID, string status, Dictionary<string,string> attributes);
```


The CognitoUserManager class exposes the following method to add the CognitoUser to the pool:

```csharp
/// <summary>
/// Creates the specified <paramref name="user"/> in Cognito with a generated password sent to the user,
/// as an asynchronous operation.
/// </summary>
/// <param name="user">The user to create.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> CreateAsync(TUser user);
```

A full example of user creation is available in the [sample web application.](https://github.com/aws/aws-aspnet-cognito-identity-provider/blob/master/samples/Samples/Areas/Identity/Pages/Account/Register.cshtml.cs#L71)


## Confirm a CognitoUser Sign up using the confirmation token

Once the CognitoUser added to the pool, a confirmation token is sent either to the CognitoUser email or phone number.

The CognitoUserManager class exposes the following method to verify the CognitoUser account. It also verifies the medium used to receive the token:

```csharp
/// <summary>
/// Confirms the specified <paramref name="user"/> account with the specified
/// <paramref name="confirmationCode"/> he was sent by email or sms,
/// as an asynchronous operation.
/// When a new user is confirmed, the user's attribute through which the 
/// confirmation code was sent (email address or phone number) is marked as verified. 
/// If this attribute is also set to be used as an alias, then the user can sign in with
/// that attribute (email address or phone number) instead of the username.
/// </summary>
/// <param name="user">The user to confirm.</param>
/// <param name="confirmationCode">The confirmation code that was sent by email or sms.</param>
/// <param name="forcedAliasCreation">If set to true, this resolves potential alias conflicts by marking the attribute email or phone number verified.
/// If set to false and an alias conflict exists, then the user confirmation will fail.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> ConfirmSignUpAsync(TUser user, string confirmationCode, bool forcedAliasCreation);
```

## Confirm a CognitoUser Sign up using Admin privileges

Once the CognitoUser added to the pool, a confirmation token is sent either to the CognitoUser email or phone number. You can force the confirmation of the CognitoUser account using the following method of the CognitoUserManager, regardless of the confirmation token:

```csharp
/// <summary>
/// Admin confirms the specified <paramref name="user"/> 
/// as an asynchronous operation.
/// </summary>
/// <param name="user">The user to confirm.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> AdminConfirmSignUpAsync(TUser user);
```

**Note: this does not confirm the medium used to receive the confirmation token (phone number or email).**

## Resend the CognitoUser sign up confirmation token

The CognitoUserManager class exposes the following method to resend the CognitoUser sign up confirmation token:

```csharp
/// <summary>
/// Resends the account signup confirmation code for the specified <paramref name="user"/>
/// as an asynchronous operation.
/// </summary>
/// <param name="user">The user to resend the account signup confirmation code for.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> ResendSignupConfirmationCodeAsync(TUser user);
```
## Update a CognitoUser attributes

After making changes to a CognitoUser attributes property, you can call the following method on the CognitoUserManager class:

```csharp
/// <summary>
/// Updates the user attributes. 
/// </summary>
/// <param name="user">The user with the new attributes values changed.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> UpdateUserAsync(TUser user);
```

## Delete a CognitoUser from the pool

The CognitoUserManager class exposes the following method to delete a user from the pool:

```csharp
/// <summary>
/// Deletes the specified <paramref name="user"/> from the user pool.
/// </summary>
/// <param name="user">The user to delete.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> DeleteAsync(TUser user);
```


