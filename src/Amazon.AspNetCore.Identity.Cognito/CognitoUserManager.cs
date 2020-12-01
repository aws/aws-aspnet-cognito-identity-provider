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
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Amazon.CognitoIdentityProvider;

namespace Amazon.AspNetCore.Identity.Cognito
{
    public class CognitoUserManager<TUser> : UserManager<TUser> where TUser : CognitoUser
    {
        // This specific type is needed to accomodate all the interfaces it implements.
        private readonly CognitoUserStore<TUser> _userStore;
        private IHttpContextAccessor _httpContextAccessor;

        public CognitoUserManager(IUserStore<TUser> store, 
            IOptions<IdentityOptions> optionsAccessor, 
            IPasswordHasher<TUser> passwordHasher, 
            IEnumerable<IUserValidator<TUser>> userValidators, 
            IEnumerable<IPasswordValidator<TUser>> passwordValidators, 
            CognitoKeyNormalizer keyNormalizer, 
            IdentityErrorDescriber errors, 
            IServiceProvider services, 
            ILogger<UserManager<TUser>> logger,
            IHttpContextAccessor httpContextAccessor) : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
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

            _httpContextAccessor = httpContextAccessor ?? throw new ArgumentException(nameof(httpContextAccessor));
        }

        /// <summary>
        /// Gets the user, if any, associated with the normalized value of the specified email address.
        /// </summary>
        /// <param name="email">The email address to return the user for.</param>
        /// <returns>
        /// The task object containing the results of the asynchronous lookup operation, the user, if any, associated with a normalized value of the specified email address.
        /// </returns>
        public override async Task<TUser> FindByEmailAsync(string email)
        {
            ThrowIfDisposed();
            if (email == null)
            {
                throw new ArgumentNullException(nameof(email));
            }
#if NETCOREAPP_3_0
            email = NormalizeEmail(email);
#endif
#if NETSTANDARD_2_0
            email = NormalizeKey(email);
#endif
            var user = await _userStore.FindByEmailAsync(email, CancellationToken).ConfigureAwait(false);
            if (user != null)
            {
                await PopulateTokens(user, ClaimTypes.Email, email).ConfigureAwait(false);
            }
            return user;
        }

        /// <summary>
        /// Finds and returns a user, if any, who has the specified <paramref name="userId"/>.
        /// </summary>
        /// <param name="userId">The user ID to search for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userId"/> if it exists.
        /// </returns>
        public override async Task<TUser> FindByIdAsync(string userId)
        {
            ThrowIfDisposed();
            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }
            var user = await _userStore.FindByIdAsync(userId, CancellationToken).ConfigureAwait(false);
            if (user != null)
            {
                await PopulateTokens(user, ClaimTypes.Name, userId).ConfigureAwait(false);
            }
            return user;
        }

        /// <summary>
        /// Finds and returns a user, if any, who has the specified user name.
        /// </summary>
        /// <param name="userName">The user name to search for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userName"/> if it exists.
        /// </returns>
        public override async Task<TUser> FindByNameAsync(string userName)
        {
            ThrowIfDisposed();
            if (userName == null)
            {
                throw new ArgumentNullException(nameof(userName));
            }
#if NETCOREAPP_3_0
            userName = NormalizeName(userName);
#endif
#if NETSTANDARD_2_0
            userName = NormalizeKey(userName);
#endif
            var user = await _userStore.FindByNameAsync(userName, CancellationToken).ConfigureAwait(false);
            if (user != null)
            {
                await PopulateTokens(user, ClaimTypes.Name, userName).ConfigureAwait(false);
            }
            return user;
        }

        /// <summary>
        /// Populates the user SessionToken object if he satisfies the claimType and claimValue parameters
        /// </summary>
        /// <param name="user">The user to populate tokens for.</param>
        /// <param name="claimType">The claim type to check.</param>
        /// <param name="claimValue">The claim value to check.</param>
        private async Task PopulateTokens(TUser user, string claimType, string claimValue)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            // First check if the current user is authenticated before calling AuthenticateAsync() or the call may hang.
            if (_httpContextAccessor?.HttpContext?.User?.Identity?.IsAuthenticated == true)
            {
                var result = await _httpContextAccessor.HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme).ConfigureAwait(false);

                if (result?.Principal?.Claims != null)
                {
                    if (result.Principal.Claims.Any(claim => claim.Type == claimType && claim.Value == claimValue))
                    {
                        var accessToken = await _httpContextAccessor.HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken).ConfigureAwait(false);
                        var refreshToken = await _httpContextAccessor.HttpContext.GetTokenAsync(OpenIdConnectParameterNames.RefreshToken).ConfigureAwait(false);
                        var idToken = await _httpContextAccessor.HttpContext.GetTokenAsync(OpenIdConnectParameterNames.IdToken).ConfigureAwait(false);

                        user.SessionTokens = new CognitoUserSession(idToken, accessToken, refreshToken, result.Properties.IssuedUtc.Value.DateTime, result.Properties.ExpiresUtc.Value.DateTime);
                    }
                }
            }           
        }

        public override Task<bool> VerifyTwoFactorTokenAsync(TUser user, string tokenProvider, string token)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return _userStore.VerifyTwoFactorTokenAsync(user,tokenProvider, token);
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
        public virtual Task<AuthFlowResponse> CheckPasswordAsync(TUser user, string password)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return _userStore.StartValidatePasswordAsync(user, password, CancellationToken);
        }

        /// <summary>
        /// Checks if the <param name="user"> can log in with the specified 2fa code challenge <paramref name="code"/>.
        /// </summary>
        /// <param name="user">The user try to log in with.</param>
        /// <param name="code">The 2fa code to check</param>
        /// <param name="authWorkflowSessionId">The ongoing Cognito authentication workflow id.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the AuthFlowResponse object linked to that authentication workflow.</returns>
        public virtual Task<AuthFlowResponse> RespondToTwoFactorChallengeAsync(TUser user, string code, string authWorkflowSessionId, string challengeType)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return _userStore.RespondToTwoFactorChallengeAsync(user, code, authWorkflowSessionId, challengeType, CancellationToken);
        }

        public override async Task<string> GetAuthenticatorKeyAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var key = await _userStore.GetAuthenticatorKeyAsync(user, CancellationToken.None).ConfigureAwait(false);

            return key;
        }

        /// <summary>
        /// Sets a flag indicating whether the specified <paramref name="user"/> has two factor authentication enabled or not,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose two factor authentication enabled status should be set.</param>
        /// <param name="enabled">A flag indicating whether the specified <paramref name="user"/> has two factor authentication enabled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, the <see cref="IdentityResult"/> of the operation
        /// </returns>
        public override async Task<IdentityResult> SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            await _userStore.SetTwoFactorEnabledAsync(user, enabled, CancellationToken).ConfigureAwait(false);
            return IdentityResult.Success;
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
        public override Task<IdentityResult> ChangePasswordAsync(TUser user, string currentPassword, string newPassword)
        {
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return _userStore.ChangePasswordAsync(user, currentPassword, newPassword, CancellationToken);
        }

        /// <summary>
        /// Checks if the password needs to be changed for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to check if the password needs to be changed.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if the password needs to be changed, false otherwise.</returns>
        public virtual Task<bool> IsPasswordChangeRequiredAsync(TUser user)
        {
            ThrowIfDisposed();
            return _userStore.IsPasswordChangeRequiredAsync(user, CancellationToken);
        }

        /// <summary>
        /// Checks if the password needs to be reset for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to check if the password needs to be reset.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if the password needs to be reset, false otherwise.</returns>
        public virtual Task<bool> IsPasswordResetRequiredAsync(TUser user)
        {
            ThrowIfDisposed();
            return _userStore.IsPasswordResetRequiredAsync(user, CancellationToken);
        }

        /// <summary>
        /// Resets the <paramref name="user"/>'s password to the specified <paramref name="newPassword"/> after
        /// validating the given password reset <paramref name="token"/>.
        /// </summary>
        /// <param name="user">The user whose password should be reset.</param>
        /// <param name="token">The password reset token to verify.</param>
        /// <param name="newPassword">The new password to set if reset token verification succeeds.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public override Task<IdentityResult> ResetPasswordAsync(TUser user, string token, string newPassword)
        {
            ThrowIfDisposed();

            return _userStore.ChangePasswordWithTokenAsync(user, token, newPassword, CancellationToken);
        }

        /// <summary>
        /// Resets the <paramref name="user"/>'s password and sends the confirmation token to the user 
        /// via email or sms depending on the user pool policy.
        /// </summary>
        /// <param name="user">The user whose password should be reset.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public Task<IdentityResult> ResetPasswordAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return _userStore.ResetPasswordAsync(user, CancellationToken);
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
        public override Task<IdentityResult> CreateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return _userStore.CreateAsync(user, CancellationToken);
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
        public override Task<IdentityResult> CreateAsync(TUser user, string password)
        {
            ThrowIfDisposed();

            return CreateAsync(user, password, null);
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
            throw new NotSupportedException("Cognito does not support directly retrieving the token value. Use SendEmailConfirmationTokenAsync() instead.");
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
            throw new NotSupportedException("Cognito does not support directly retrieving the token value. Use SendPhoneConfirmationTokenAsync() instead.");
        }

        /// <summary>
        /// Generates and sends an email confirmation token for the specified user.
        /// </summary>
        /// <param name="user">The user to generate and send an email confirmation token for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual Task<IdentityResult> SendEmailConfirmationTokenAsync(TUser user)
        {
            ThrowIfDisposed();

            return _userStore.GetUserAttributeVerificationCodeAsync(user, CognitoAttribute.Email.AttributeName, CancellationToken);
        }

        public virtual Task ForgotPasswordAsync(TUser user)
        {
            ThrowIfDisposed();

            return _userStore.ForgotPasswordAsync(user);
        }

        /// <summary>
        /// Generates and sends a phone confirmation token for the specified user.
        /// </summary>
        /// <param name="user">The user to generate and send a phone confirmation token for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual Task<IdentityResult> SendPhoneConfirmationTokenAsync(TUser user)
        {
            ThrowIfDisposed();

            return _userStore.GetUserAttributeVerificationCodeAsync(user, CognitoAttribute.PhoneNumber.AttributeName, CancellationToken);
        }

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
        public override Task<IdentityResult> ConfirmEmailAsync(TUser user, string confirmationCode)
        {
            ThrowIfDisposed();

            return _userStore.VerifyUserAttributeAsync(user, CognitoAttribute.Email.AttributeName, confirmationCode, CancellationToken);
        }

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
        public Task<IdentityResult> ConfirmPhoneNumberAsync(TUser user, string confirmationCode)
        {
            ThrowIfDisposed();

            return _userStore.VerifyUserAttributeAsync(user, CognitoAttribute.PhoneNumber.AttributeName, confirmationCode, CancellationToken);
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
        public virtual Task<IdentityResult> ConfirmSignUpAsync(TUser user, string confirmationCode, bool forcedAliasCreation)
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
            return _userStore.ConfirmSignUpAsync(user, confirmationCode, forcedAliasCreation, CancellationToken);
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
        public virtual Task<IdentityResult> AdminConfirmSignUpAsync(TUser user)
        {
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return _userStore.AdminConfirmSignUpAsync(user, CancellationToken);
        }

        /// <summary>
        /// Resends the account signup confirmation code for the specified <paramref name="user"/>
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to resend the account signup confirmation code for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual Task<IdentityResult> ResendSignupConfirmationCodeAsync(TUser user)
        {
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return _userStore.ResendSignupConfirmationCodeAsync(user, CancellationToken);
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
            throw new NotSupportedException("Cognito does not support changing and confirming the email simultaneously, use SetEmailAsync() and ConfirmEmailAsync()");
        }

        /// <summary>
        /// Updates the user attributes. 
        /// </summary>
        /// <param name="user">The user with the new attributes values changed.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        protected override Task<IdentityResult> UpdateUserAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return _userStore.UpdateAsync(user, CancellationToken);
        }

        /// <summary>
        ///  Not supported: Returns an IQueryable of users if the store is an IQueryableUserStore
        /// </summary>
        public override IQueryable<TUser> Users => throw new NotSupportedException("This property is not supported. Use GetUsersAsync() instead.");

        /// <summary>
        /// Queries Cognito and returns the users in the pool. Optional filters can be applied on the users to retrieve based on their attributes.
        /// Providing an empty attributeFilterName parameter returns all the users in the pool.
        /// </summary>
        /// <param name="attributeFilterName"> The attribute name to filter your search on. You can only search for the following standard attributes:
        ///     username (case-sensitive)
        ///     email
        ///     phone_number
        ///     name
        ///     given_name
        ///     family_name
        ///     preferred_username
        ///     cognito:user_status (called Status in the Console) (case-insensitive)
        ///     status (called Enabled in the Console) (case-sensitive)
        ///     sub
        ///     Custom attributes are not searchable.
        ///     For more information, see Searching for Users Using the ListUsers API and Examples
        ///     of Using the ListUsers API in the Amazon Cognito Developer Guide.</param>
        /// <param name="attributeFilterType"> The type of filter to apply:
        ///     For an exact match, use =
        ///     For a prefix ("starts with") match, use ^=
        /// </param>
        /// <param name="attributeFilterValue"> The filter value for the specified attribute.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing a IEnumerable of CognitoUser.
        /// </returns>
        public virtual Task<IEnumerable<CognitoUser>> GetUsersAsync(CognitoAttribute filterAttribute = null, CognitoAttributeFilterType filterType = null, string filterValue = "")
        {
            ThrowIfDisposed();
            return _userStore.GetUsersAsync(filterAttribute, filterType, filterValue, CancellationToken);
        }

        /// <summary>
        /// Adds the specified <paramref name="claims"/> to the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the claim to.</param>
        /// <param name="claims">The claims to add.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public override async Task<IdentityResult> AddClaimsAsync(TUser user, IEnumerable<Claim> claims)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            await _userStore.AddClaimsAsync(user, claims, CancellationToken).ConfigureAwait(false);
            return IdentityResult.Success;
        }

        /// <summary>
        /// Removes the specified <paramref name="claims"/> from the given <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the specified <paramref name="claims"/> from.</param>
        /// <param name="claims">A collection of <see cref="Claim"/>s to remove.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public override async Task<IdentityResult> RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            await _userStore.RemoveClaimsAsync(user, claims, CancellationToken).ConfigureAwait(false);
            return IdentityResult.Success;
        }
    }
}
