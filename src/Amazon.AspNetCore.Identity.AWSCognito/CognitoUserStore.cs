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

using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.AWSCognito
{
    public class CognitoUserStore<TUser> :
        IUserRoleStore<TUser>,
        IUserCognitoStore<TUser>,
        IUserClaimStore<TUser> where TUser : CognitoUser
    {
        private AmazonCognitoIdentityProviderClient _provider;
        private CognitoUserPool _pool;
        private ILogger _logger;

        public CognitoUserStore(AmazonCognitoIdentityProviderClient provider, CognitoUserPool pool, ILogger<CognitoUserStore<TUser>> logger)
        {
            _provider = provider ?? throw new ArgumentNullException(nameof(provider));
            _pool = pool ?? throw new ArgumentNullException(nameof(pool));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public void Dispose()
        {

        }

        #region IUserRoleStore

        /// <summary>
        /// Finds and returns a user, if any, who has the specified <paramref name="userId"/>.
        /// </summary>
        /// <param name="userId">The user ID to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userId"/> if it exists.
        /// </returns>
        public async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // The userId can be the userName, the email or the phone number depending on the User Pool login policy
            var user = await _pool.FindByIdAsync(userId).ConfigureAwait(false);
            return user as TUser;
        }

        /// <summary>
        /// Returns the userId associated with the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to retrieve the id for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the userId belonging to the matching the specified <paramref name="userId"/>.
        /// </returns>
        public Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(user.UserID);
        }

        /// <summary>
        /// Returns the UserName associated with the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to retrieve the UserName for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the UserName belonging to the matching the specified <paramref name="userId"/>.
        /// </returns>
        public Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(user.Username);
        }

        #region NotImplemented

        public Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            // Cognito is case-sensitive and does not support normalized user name.
            throw new NotImplementedException();
        }

        public Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            // Cognito is case-sensitive and does not support normalized user name.
            throw new NotImplementedException();
        }

        public Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken)
        {
            // Cognito is case-sensitive and does not support normalized user name.
            throw new NotImplementedException();
        }

        public Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        #endregion

        #region UserRoles
        // Roles Handling:
        public Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            //WIP: AdminAddUserToGroupAsync
            throw new NotImplementedException();
        }

        public Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            //WIP: AdminRemoveUserFromGroupAsync
            throw new NotImplementedException();
        }

        public Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken)
        {
            //WIP: ListGroupsAsync
            throw new NotImplementedException();
        }

        public Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            //WIP: AdminListGroupsForUserAsync
            throw new NotImplementedException();
        }

        public Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            //WIP: ListUsersInGroupAsync
            throw new NotImplementedException();
        }
        #endregion

        #endregion

        #region IUserCognitoStore

        /// <summary>
        /// Checks if the <param name="user"> can log in with the specified password <paramref name="password"/>.
        /// </summary>
        /// <param name="user">The user try to log in with.</param>
        /// <param name="password">The password supplied for validation.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the AuthFlowResponse object linked to that authentication workflow.</returns>
        public async Task<AuthFlowResponse> StartValidatePasswordAsync(TUser user, string password, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                AuthFlowResponse context =
                    await user.StartWithSrpAuthAsync(new InitiateSrpAuthRequest()
                    {
                        Password = password
                    }).ConfigureAwait(false);

                return context;
            }
            catch (NotAuthorizedException)
            {
                // If the password validation fails then the response flow should be set to null.
                return null;
            }
        }

        /// <summary>
        /// Changes the passowrd on the cognito account associated with the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to change the password for.</param>
        /// <param name="currentPassword">The current password of the user.</param>
        /// <param name="newPassword">The new passord for the user.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if changing the password was successful, false otherwise.</returns>
        public async Task<bool> ChangePasswordAsync(TUser user, string currentPassword, string newPassword, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // We start an auth process as the user needs a valid session id to be able to change it's password.
            var authResult = await StartValidatePasswordAsync(user, currentPassword, cancellationToken);
            if (authResult.ChallengeName == ChallengeNameType.NEW_PASSWORD_REQUIRED || (user.SessionTokens != null && user.SessionTokens.IsValid()))
            {
                await user.ChangePasswordAsync(currentPassword, newPassword).ConfigureAwait(false);
                return true;
            }
            else
                return false;
        }

        /// <summary>
        /// Checks if the password needs to be changed for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to check if the password needs to be changed.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if the password needs to be changed, false otherwise.</returns>
        public Task<bool> IsPasswordChangeRequiredAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            bool IsPasswordChangeRequired = user.Status.Equals(CognitoConstants.StatusForceChangePassword) || user.Status.Equals(CognitoConstants.StatusResetRequired);
            return Task.FromResult(IsPasswordChangeRequired);
        }

        /// <summary>
        /// Resets the password for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to reset the password for.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if the password was reset, false otherwise.</returns>
        public async Task<bool> ResetUserPasswordAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var request = new AdminResetUserPasswordRequest
            {
                Username = user.Username,
                UserPoolId = _pool.PoolID
            };

           await _provider.AdminResetUserPasswordAsync(request);

           return true;
        }

        #endregion

        #region IUserClaimStore

        /// <summary>
        /// Gets a list of <see cref="Claim"/>s to be belonging to the specified <paramref name="user"/> as an asynchronous operation.
        /// </summary>
        /// <param name="user">The role whose claims to retrieve.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// A <see cref="Task{TResult}"/> that represents the result of the asynchronous query, a list of <see cref="Claim"/>s.
        /// </returns>
        public async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IList<Claim> claims = new List<Claim>();
            if (user.Attributes == null) // Attributes are not set, fetching them
            {
                var details = await user.GetUserDetailsAsync();
                details.UserAttributes.ForEach(item => claims.Add(new Claim(item.Name, item.Value)));
            }
            else
            {
                foreach (var item in user.Attributes)
                {
                    claims.Add(new Claim(item.Key, item.Value));
                }
            }

            return claims;
        }

        /// <summary>
        /// Add claims to a user as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to add the claim to.</param>
        /// <param name="claims">The collection of <see cref="Claim"/>s to add.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Replaces the given <paramref name="claim"/> on the specified <paramref name="user"/> with the <paramref name="newClaim"/>
        /// </summary>
        /// <param name="user">The user to replace the claim on.</param>
        /// <param name="claim">The claim to replace.</param>
        /// <param name="newClaim">The new claim to replace the existing <paramref name="claim"/> with.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            //For custom attributes, you must prepend the custom: prefix to the attribute name.
            throw new NotImplementedException();
        }

        /// <summary>
        /// Removes the specified <paramref name="claims"/> from the given <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the specified <paramref name="claims"/> from.</param>
        /// <param name="claims">A collection of <see cref="Claim"/>s to remove.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Returns a list of users who contain the specified <see cref="Claim"/>.
        /// </summary>
        /// <param name="claim">The claim to look for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// A <see cref="Task{TResult}"/> that represents the result of the asynchronous query, a list of <typeparamref name="TUser"/> who
        /// contain the specified claim.
        /// </returns>
        public Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
        #endregion
    }
}
