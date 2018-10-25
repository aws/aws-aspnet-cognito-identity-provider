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

            var userStore = store as CognitoUserStore<TUser>;
            if (userStore == null)
            {
                throw new ArgumentException("The store must be of type CognitoUserStore<TUser>", nameof(store));
            }
            else
            {
                _userStore = userStore;
            }
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

            return await _userStore.ChangePasswordAsync(user, currentPassword, newPassword, CancellationToken).ConfigureAwait(false);
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
        public override Task<IdentityResult> ResetPasswordAsync(TUser user, string token, string newPassword)
        {
            throw new NotImplementedException("This is not supported by Cognito. Use the ResetPasswordAsync(TUser user) overload instead.");
        }

        /// <summary>
        /// Resets the <paramref name="user"/>'s password and sends the new password to the user 
        /// via email or sms depending on the user pool policy.
        /// </summary>
        /// <param name="user">The user whose password should be reset.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public async Task<IdentityResult> ResetPasswordAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return await _userStore.ResetUserPasswordAsync(user, CancellationToken).ConfigureAwait(false);
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

            return await _userStore.CreateAsync(user, CancellationToken).ConfigureAwait(false);
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

        /// <summary>
        /// Generates an email confirmation token for the specified user.
        /// </summary>
        /// <param name="user">The user to generate an email confirmation token for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, an email confirmation token.
        /// </returns>
        public override Task<string> GenerateEmailConfirmationTokenAsync(TUser user)
        {
            throw new NotImplementedException("Cognito does not support directly retrieving the token value. Use SendEmailConfirmationTokenAsync() instead.");
        }

        /// <summary>
        /// Generates a telephone number change token for the specified user.
        /// </summary>
        /// <param name="user">The user to generate a telephone number token for.</param>
        /// <param name="phoneNumber">The new phone number the validation token should be sent to.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the telephone change number token.
        /// </returns>
        public override Task<string> GenerateChangePhoneNumberTokenAsync(TUser user, string phoneNumber)
        {
            throw new NotImplementedException("Cognito does not support directly retrieving the token value. Use SendPhoneConfirmationTokenAsync() instead.");
        }

        /// <summary>
        /// Generates and sends an email confirmation token for the specified user.
        /// </summary>
        /// <param name="user">The user to generate and send an email confirmation token for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public async virtual Task<IdentityResult> SendEmailConfirmationTokenAsync(TUser user)
        {
            ThrowIfDisposed();

            return await _userStore.GetUserAttributeVerificationCodeAsync(user, CognitoStandardAttributes.Email, CancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Generates and sends a phone confirmation token for the specified user.
        /// </summary>
        /// <param name="user">The user to generate and send a phone confirmation token for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public async virtual Task<IdentityResult> SendPhoneConfirmationTokenAsync(TUser user)
        {
            ThrowIfDisposed();

            return await _userStore.GetUserAttributeVerificationCodeAsync(user, CognitoStandardAttributes.PhoneNumber, CancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Confirms the email of an user by validating that an email confirmation token is valid for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to validate the token against.</param>
        /// <param name="confirmationCode">The email confirmation code to validate.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public override async Task<IdentityResult> ConfirmEmailAsync(TUser user, string confirmationCode)
        {
            ThrowIfDisposed();

            return await _userStore.VerifyUserAttributeAsync(user, CognitoStandardAttributes.Email, confirmationCode, CancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Confirms the phone number of an user by validating that an email confirmation token is valid for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to validate the token against.</param>
        /// <param name="confirmationCode">The phone number confirmation code to validate.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public async Task<IdentityResult> ConfirmPhoneNumberAsync(TUser user, string confirmationCode)
        {
            ThrowIfDisposed();

            return await _userStore.VerifyUserAttributeAsync(user, CognitoStandardAttributes.PhoneNumber, confirmationCode, CancellationToken).ConfigureAwait(false);
        }

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
        public virtual async Task<IdentityResult> ConfirmSignUpAsync(TUser user, string confirmationCode, bool forcedAliasCreation)
        {
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrWhiteSpace(confirmationCode))
            {
                throw new ArgumentException("The confirmation code can not be null or blank", nameof(confirmationCode));
            }
            return await _userStore.ConfirmSignUpAsync(user, confirmationCode, forcedAliasCreation, CancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Admin confirms the specified <paramref name="user"/> 
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to confirm.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> AdminConfirmSignUpAsync(TUser user)
        {
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return await _userStore.AdminConfirmSignUpAsync(user, CancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Sets the phone number for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose phone number to set.</param>
        /// <param name="phoneNumber">The phone number to set.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public override async Task<IdentityResult> SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            await _userStore.SetPhoneNumberAsync(user, phoneNumber, CancellationToken).ConfigureAwait(false);
            return await UpdateUserAsync(user).ConfigureAwait(false);
        }

        /// <summary>
        /// Sets the <paramref name="email"/> address for a <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose email should be set.</param>
        /// <param name="email">The email to set.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public override async Task<IdentityResult> SetEmailAsync(TUser user, string email)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            await _userStore.SetEmailAsync(user, email, CancellationToken).ConfigureAwait(false);
            return await UpdateUserAsync(user).ConfigureAwait(false);
        }

        /// <summary>
        /// Updates a users emails if the specified email change <paramref name="token"/> is valid for the user.
        /// </summary>
        /// <param name="user">The user whose email should be updated.</param>
        /// <param name="newEmail">The new email address.</param>
        /// <param name="token">The change email token to be verified.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public override Task<IdentityResult> ChangeEmailAsync(TUser user, string newEmail, string token)
        {
            throw new NotImplementedException("Cognito does not support changing and confirming the email simultaneously, use SetEmailAsync() and ConfirmEmailAsync()");
        }

        /// <summary>
        /// Updates the user attributes. 
        /// </summary>
        /// <param name="user">The user with the new attributes values changed.</param>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        protected override async Task<IdentityResult> UpdateUserAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return await _userStore.UpdateAsync(user, CancellationToken).ConfigureAwait(false);
        }
    }
}
