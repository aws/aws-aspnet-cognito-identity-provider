/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 * 
 *  http://aws.amazon.com/apache2.0
 * 
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

using Amazon.AspNetCore.Identity.Cognito.Exceptions;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.Cognito
{
    public partial class CognitoUserStore<TUser> : IUserClaimStore<TUser> where TUser : CognitoUser
    {
        /// <summary>
        /// Gets a list of <see cref="Claim"/>s to be belonging to the specified <paramref name="user"/> as an asynchronous operation.
        /// </summary>
        /// <param name="user">The role whose claims to retrieve.</param>
        /// <returns>
        /// A <see cref="Task{TResult}"/> that represents the result of the asynchronous query, a list of <see cref="Claim"/>s.
        /// </returns>
        public virtual async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            try
            {
                var details = await _cognitoClient.AdminGetUserAsync(new AdminGetUserRequest
                {

                    Username = user.Username,
                    UserPoolId = _pool.PoolID
                }, cancellationToken).ConfigureAwait(false);

                return details.UserAttributes.Select(att => new Claim(att.Name, att.Value)).ToList();
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                throw new CognitoServiceException("Failed to retrieve Cognito User claims", e);
            }
        }

        /// <summary>
        /// Add claims to a user as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to add the claim to.</param>
        /// <param name="claims">The collection of <see cref="Claim"/>s to add.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public virtual async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            if (claims.Any())
            {
                try
                {
                    await _cognitoClient.AdminUpdateUserAttributesAsync(new AdminUpdateUserAttributesRequest
                    {
                        UserAttributes = CreateAttributeList(claims.ToDictionary(claim => claim.Type, claim => claim.Value)),
                        Username = user.Username,
                        UserPoolId = _pool.PoolID
                    }, cancellationToken).ConfigureAwait(false);
                }
                catch (AmazonCognitoIdentityProviderException e)
                {
                    throw new CognitoServiceException("Failed to add a claim to the Cognito User", e);
                }
            }
        }

        /// <summary>
        /// Replaces the given <paramref name="claim"/> on the specified <paramref name="user"/> with the <paramref name="newClaim"/>
        /// </summary>
        /// <param name="user">The user to replace the claim on.</param>
        /// <param name="claim">The claim to replace.</param>
        /// <param name="newClaim">The new claim to replace the existing <paramref name="claim"/> with.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            throw new NotSupportedException("Cognito does not support replacing claims. Call RemoveClaimsAsync() and AddClaimsAsync() instead.");
        }

        /// <summary>
        /// Removes the specified <paramref name="claims"/> from the given <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the specified <paramref name="claims"/> from.</param>
        /// <param name="claims">A collection of <see cref="Claim"/>s to remove.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public virtual async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            var userClaims = await GetClaimsAsync(user, cancellationToken).ConfigureAwait(false);

            // Only removes the claims that the user actually have.
            var matchedClaims = userClaims.Select(claim => new { claim.Type, claim.Value })
                                            .Intersect(claims.Select(claim => new { claim.Type, claim.Value }));

            if (matchedClaims.Any())
            {
                try
                {
                    await _cognitoClient.AdminDeleteUserAttributesAsync(new AdminDeleteUserAttributesRequest
                    {
                        UserAttributeNames = matchedClaims.Select(claim => claim.Type).ToList(),
                        Username = user.Username,
                        UserPoolId = _pool.PoolID
                    }, cancellationToken).ConfigureAwait(false);
                }
                catch (AmazonCognitoIdentityProviderException e)
                {
                    throw new CognitoServiceException("Failed to remove a claim from the Cognito User", e);
                }
            }
        }

        /// <summary>
        /// Returns a list of users who contain the specified <see cref="Claim"/>.
        /// </summary>
        /// <param name="claim">The claim to look for.</param>
        /// <returns>
        /// A <see cref="Task{TResult}"/> that represents the result of the asynchronous query, a list of <typeparamref name="TUser"/> who
        /// contain the specified claim.
        /// </returns>
        public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            if (CognitoAttribute.FilterableAttributes.Contains(claim.Type))
            {
                try
                {
                    var response = await _cognitoClient.ListUsersAsync(new ListUsersRequest
                    {
                        Filter = claim.Type + "=\"" + claim.Value + "\"",
                        UserPoolId = _pool.PoolID
                    }, cancellationToken).ConfigureAwait(false);

                    return response.Users.Select(user => _pool.GetUser(user.Username, user.UserStatus,
                        user.Attributes.ToDictionary(att => att.Name, att => att.Value))).ToList() as IList<TUser>;
                }
                catch (AmazonCognitoIdentityProviderException e)
                {
                    throw new CognitoServiceException("Failed to get the list of users for a specific claim", e);
                }
            }
            else
            {
                throw new NotSupportedException(String.Format("Retrieving the list of users with the claim type {0} is not supported", claim.Type));
            }
        }
    }
}
