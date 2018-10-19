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
using System.Linq;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.AWSCognito
{
    public class CognitoUserManager<TUser> : UserManager<TUser> where TUser : CognitoUser
    {
        // This specific type is needed to accomodate all the interfaces it implements.
        private readonly CognitoUserStore<TUser> _userStore;

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

            if (store is CognitoUserStore<TUser>)
                _userStore = store as CognitoUserStore<TUser>;
            else
                throw new ArgumentException("The store must be of type CognitoUserStore<TUser>", nameof(store));
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

        /// <summary>
        /// Creates the specified <paramref name="user"/> in Cognito with a generated password sent to the user,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public override async Task<IdentityResult> CreateAsync(TUser user)
        {
            ThrowIfDisposed();

            return await _userStore.CreateAsync(user, CancellationToken);
        }

        /// <summary>
        /// Creates the specified <paramref name="user"/> in Cognito with the given password,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <param name="password">The password for the user.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public override async Task<IdentityResult> CreateAsync(TUser user, string password)
        {
            ThrowIfDisposed();

            return await CreateAsync(user, password, null).ConfigureAwait(false);
        }

        /// <summary>
        /// Creates the specified <paramref name="user"/> in Cognito with the given password and validation data,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <param name="password">The password for the user</param>
        /// <param name="validationData">The validation data to be sent to the pre sign-up lambda triggers.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public async Task<IdentityResult> CreateAsync(TUser user, string password, IDictionary<string, string> validationData)
        {
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }
            var validate = await ValidatePasswordInternal(user, password).ConfigureAwait(false);
            if (!validate.Succeeded)
            {
                return validate;
            }

            var result = await _userStore.CreateAsync(user, password, validationData, CancellationToken).ConfigureAwait(false);

            return result;
        }

        /// <summary>
        /// Validates the given password against injected IPasswordValidator password validators,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to validate the password for.</param>
        /// <param name="password">The password to validate.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        private async Task<IdentityResult> ValidatePasswordInternal(TUser user, string password)
        {
            var errors = new List<IdentityError>();
            foreach (var v in PasswordValidators)
            {
                var result = await v.ValidateAsync(this, user, password).ConfigureAwait(false);
                if (!result.Succeeded)
                {
                    errors.AddRange(result.Errors);
                }
            }
            if (errors.Count > 0)
            {
                Logger.LogWarning(14, "User {userId} password validation failed: {errors}.", await GetUserIdAsync(user).ConfigureAwait(false), string.Join(";", errors.Select(e => e.Code)));
                return IdentityResult.Failed(errors.ToArray());
            }
            return IdentityResult.Success;
        }
    }
}
