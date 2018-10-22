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
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.AWSCognito
{
    public partial class CognitoUserStore<TUser> : IUserCognitoStore<TUser> where TUser : CognitoUser
    {
        private AmazonCognitoIdentityProviderClient _provider;
        private CognitoUserPool _pool;

        public CognitoUserStore(AmazonCognitoIdentityProviderClient provider, CognitoUserPool pool)
        {
            _provider = provider ?? throw new ArgumentNullException(nameof(provider));
            _pool = pool ?? throw new ArgumentNullException(nameof(pool));
        }

        #region IDisposable
        private bool disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (disposed)
                return; 

            if (disposing)
            {
                _provider.Dispose();
            }
            
            disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
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
            var authResult = await StartValidatePasswordAsync(user, currentPassword, cancellationToken).ConfigureAwait(false);
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
            bool IsPasswordChangeRequired = user.Status.Equals(CognitoConstants.StatusForceChangePassword, StringComparison.InvariantCulture) || user.Status.Equals(CognitoConstants.StatusResetRequired, StringComparison.InvariantCulture);
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

            await _provider.AdminResetUserPasswordAsync(request).ConfigureAwait(false);

            return true;
        }

        #endregion
    }
}
