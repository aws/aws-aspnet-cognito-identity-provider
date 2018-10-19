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

using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.AWSCognito
{
    public class CognitoUserManager<TUser> : UserManager<TUser> where TUser : CognitoUser
    {
        private readonly IUserCognitoStore<TUser> _userStore;

        public CognitoUserManager(IUserStore<TUser> store, 
            IOptions<IdentityOptions> optionsAccessor, 
            IPasswordHasher<TUser> passwordHasher, 
            IEnumerable<IUserValidator<TUser>> userValidators, 
            IEnumerable<IPasswordValidator<TUser>> passwordValidators, 
            ILookupNormalizer keyNormalizer, 
            IdentityErrorDescriber errors, 
            IServiceProvider services, 
            ILogger<UserManager<TUser>> logger) : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
            if (store == null)
                throw new ArgumentNullException(nameof(store));

            if (store is IUserCognitoStore<TUser>)
                _userStore = store as IUserCognitoStore<TUser>;
            else
                throw new ArgumentException("The store should be of type implementing IUserCognitoStore<TUser>", nameof(store));
        }

        /// <summary>
        /// Returns an AuthFlowResponse representing an authentication workflow for the specified <paramref name="password"/>
        /// and the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose password should be validated.</param>
        /// <param name="password">The password to validate</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the AuthFlowResponse object
        /// if the specified <paramref name="password" /> matches the one store for the <paramref name="user"/>,
        /// otherwise null.</returns>
        public async new Task<AuthFlowResponse> CheckPasswordAsync(TUser user, string password)
        {
            ThrowIfDisposed();
            return await _userStore.StartValidatePasswordAsync(user, password, CancellationToken).ConfigureAwait(false);
        }

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
        public override async Task<IdentityResult> ChangePasswordAsync(TUser user, string currentPassword, string newPassword)
        {
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var success = await  _userStore.ChangePasswordAsync(user, currentPassword, newPassword, CancellationToken).ConfigureAwait(false);
            if (success)
            {
                return IdentityResult.Success;
            }
            else
            {
                return IdentityResult.Failed(ErrorDescriber.PasswordMismatch()); //TODO: Create custom IdentityResult based on the errordescriber
            }
        }


        /// <summary>
        /// Checks if the password needs to be changed for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to check if the password needs to be changed.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if the password needs to be changed, false otherwise.</returns>
        public async Task<bool> IsPasswordChangeRequiredAsync(TUser user)
        {
            ThrowIfDisposed();
            return await _userStore.IsPasswordChangeRequiredAsync(user, CancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Resets the <paramref name="user"/>'s password to the specified <paramref name="newPassword"/> after
        /// validating the given password reset <paramref name="token"/>.
        /// </summary>
        /// <param name="user">The user whose password should be reset.</param>
        /// <param name="token">The password reset token to verify.</param>
        /// <param name="newPassword">The new password to set if reset token verification fails.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public override async Task<IdentityResult> ResetPasswordAsync(TUser user, string token, string newPassword)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var change = await ChangePasswordAsync(user, token, newPassword).ConfigureAwait(false);
            return change;
        }
    }
}
