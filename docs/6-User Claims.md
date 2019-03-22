![.NET on AWS Banner](./../logo.png ".NET on AWS")

# Authentication using the ASP.NET Core Identity Provider for Amazon Cognito


## Attributes to claims mapping

In this library, the CognitoUser attributes are mapped to the [Claims](https://docs.microsoft.com/en-us/dotnet/api/system.security.claims.claim?view=netcore-2.2) of the currently logged in user [after each log in.](https://github.com/aws/aws-aspnet-cognito-identity-provider/blob/master/src/Amazon.AspNetCore.Identity.Cognito/CognitoUserClaimsPrincipalFactory.cs#L60)

## The CognitoAttribute class

The ASP.NET Core Identity Provider provides a [CognitoAttribute](https://github.com/aws/aws-aspnet-cognito-identity-provider/blob/master/src/Amazon.AspNetCore.Identity.Cognito/CognitoAttribute.cs#L18) class designed to support Amazon Cognito standard attributes usecases. 

## Creating new claims

The ASP.NET Core Identity Provider maps all the attributes of the user pool, including custom attributes.

It does not support creating new custom attributes as this is a sensitive operation. **Custom attributes cannot be removed or changed once they are added to the user pool.**

For this reason, we suggest you manually create each attribute needed or carefully assess the need to programatically create them.

## Add claims for a CognitoUser

The CognitoUserManager class exposes the following methods to add one or several claims to a CognitoUser user password:

```csharp
/// <summary>
/// Adds the specified <paramref name="claim"/> to the <paramref name="user"/>.
/// </summary>
/// <param name="user">The user to add the claim to.</param>
/// <param name="claim">The claim to add.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> AddClaimAsync(TUser user, Claim claim);

/// <summary>
/// Adds the specified <paramref name="claims"/> to the <paramref name="user"/>.
/// </summary>
/// <param name="user">The user to add the claim to.</param>
/// <param name="claims">The claims to add.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> AddClaimsAsync(TUser user, IEnumerable<Claim> claims);
```
**Note: The claim type needs to be prefixed with 'custom:' if you are updating a custom attribute**

## Retrieve claims for a CognitoUser

The CognitoUserManager class exposes the following methods to retrieve the claims of a CognitoUser user password:

```csharp
/// <summary>
/// Gets a list of <see cref="Claim"/>s to be belonging to the specified <paramref name="user"/> as an asynchronous operation.
/// </summary>
/// <param name="user">The user whose claims to retrieve.</param>
/// <returns>
/// A <see cref="Task{TResult}"/> that represents the result of the asynchronous query, a list of <see cref="Claim"/>s.
/// </returns>
Task<IList<Claim>> GetClaimsAsync(TUser user);
```

## Update claims for a CognitoUser

The CognitoUserManager class exposes the following methods to update the claims of a CognitoUser user password:

```csharp
/// <summary>
/// Replaces the given <paramref name="claim"/> on the specified <paramref name="user"/> with the <paramref name="newClaim"/>
/// </summary>
/// <param name="user">The user to replace the claim on.</param>
/// <param name="claim">The claim to replace.</param>
/// <param name="newClaim">The new claim to replace the existing <paramref name="claim"/> with.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim);
```
**Note: The claim type needs to be prefixed with 'custom:' if you are updating a custom attribute**

## Remove a claims or a set of claims for a CognitoUser

The CognitoUserManager class exposes the following methods to remove the claims of a CognitoUser user password:

```csharp
/// <summary>
/// Removes the specified <paramref name="claim"/> from the given <paramref name="user"/>.
/// </summary>
/// <param name="user">The user to remove the specified <paramref name="claim"/> from.</param>
/// <param name="claim">The <see cref="Claim"/> to remove.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> RemoveClaimAsync(TUser user, Claim claim);

/// <summary>
/// Removes the specified <paramref name="claims"/> from the given <paramref name="user"/>.
/// </summary>
/// <param name="user">The user to remove the specified <paramref name="claims"/> from.</param>
/// <param name="claims">A collection of <see cref="Claim"/>s to remove.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
Task<IdentityResult> RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims);
```

**Note: The claim type needs to be prefixed with 'custom:' if you are removing a custom attribute**