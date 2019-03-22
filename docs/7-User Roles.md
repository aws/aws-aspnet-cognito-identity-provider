![.NET on AWS Banner](./../logo.png ".NET on AWS")

# Authentication using the ASP.NET Core Identity Provider for Amazon Cognito


## Attributes to roles mapping

In this library, the Cognito User Pool groups are mapped to the Roles of the currently logged-in user [after each log in.](https://github.com/aws/aws-aspnet-cognito-identity-provider/blob/master/src/Amazon.AspNetCore.Identity.Cognito/CognitoUserClaimsPrincipalFactory.cs#L71)

## The CognitoRole class

The ASP.NET Core Identity Provider provides a [CognitoRole](https://github.com/aws/aws-aspnet-cognito-identity-provider/blob/master/src/Amazon.AspNetCore.Identity.Cognito/CognitoRole.cs) class designed to support Amazon Cognito roles management. 

## Managing roles

You can use the original Identity implementation of the [RoleManager](https://github.com/aspnet/Identity/blob/eb3ff7fc32dbfff65a1ba6dfdca16487e0f6fc41/src/Microsoft.Extensions.Identity.Core/RoleManager.cs) to handle role creation, update and removal.


## Get the roles for a CognitoUser

The CognitoUserManager class exposes the following method to get all the roles of a CognitoUser:

```csharp
/// <summary>
/// Gets a list of role names the specified <paramref name="user"/> belongs to.
/// </summary>
/// <param name="user">The user whose role names to retrieve.</param>
/// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a list of role names.</returns>
Task<IList<string>> GetRolesAsync(TUser user)
```

## Check if a CognitoUser is part of a role

The CognitoUserManager class exposes the following method to check if a CognitoUser is part of a role:

```csharp
/// <summary>
/// Returns a flag indicating whether the specified <paramref name="user"/> is a member of the give named role.
/// </summary>
/// <param name="user">The user whose role membership should be checked.</param>
/// <param name="role">The name of the role to be checked.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing a flag indicating whether the specified <paramref name="user"/> is
/// a member of the named role.
/// </returns>
Task<bool> IsInRoleAsync(TUser user, string role)
```

## Adding a CognitoUser to a role

The CognitoUserManager class exposes the following methods to add a CognitoUser to a role or multiple roles:

```csharp
/// <summary>
/// Add the specified <paramref name="user"/> to the named role.
/// </summary>
/// <param name="user">The user to add to the named role.</param>
/// <param name="role">The name of the role to add the user to.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> AddToRoleAsync(TUser user, string role);

/// <summary>
/// Add the specified <paramref name="user"/> to the named roles.
/// </summary>
/// <param name="user">The user to add to the named roles.</param>
/// <param name="roles">The name of the roles to add the user to.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> AddToRolesAsync(TUser user, IEnumerable<string> roles);
```

## Remove a CognitoUser from one or several roles

The CognitoUserManager class exposes the following methods to remove a CognitoUser from one or several roles:

```csharp
/// <summary>
/// Removes the specified <paramref name="user"/> from the named role.
/// </summary>
/// <param name="user">The user to remove from the named role.</param>
/// <param name="role">The name of the role to remove the user from.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> RemoveFromRoleAsync(TUser user, string role);

/// <summary>
/// Removes the specified <paramref name="user"/> from the named roles.
/// </summary>
/// <param name="user">The user to remove from the named roles.</param>
/// <param name="roles">The name of the roles to remove the user from.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> RemoveFromRolesAsync(TUser user, IEnumerable<string> roles);
```