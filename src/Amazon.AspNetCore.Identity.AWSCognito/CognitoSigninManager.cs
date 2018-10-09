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
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.AWSCognito
{
    public class CognitoSignInManager<TUser> : SignInManager<TUser> where TUser : CognitoUser
    {
        private readonly CognitoUserManager<TUser> _userManager;
        private readonly CognitoUserClaimsPrincipalFactory<TUser> _claimsFactory;
        private readonly IHttpContextAccessor _contextAccessor;

        public CognitoSignInManager(UserManager<TUser> userManager, IHttpContextAccessor contextAccessor, IUserClaimsPrincipalFactory<TUser> claimsFactory, IOptions<IdentityOptions> optionsAccessor, ILogger<SignInManager<TUser>> logger, IAuthenticationSchemeProvider schemes) : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes)
        {
            _userManager = userManager as CognitoUserManager<TUser> ?? throw new ArgumentNullException(nameof(userManager));
            _claimsFactory = claimsFactory as CognitoUserClaimsPrincipalFactory<TUser> ?? throw new ArgumentNullException(nameof(claimsFactory));
            _contextAccessor = contextAccessor ?? throw new ArgumentNullException(nameof(contextAccessor));
        }

        /// <summary>
        /// Attempts to sign in the specified <paramref name="userName"/> and <paramref name="password"/> combination
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="userName">The user name to sign in.</param>
        /// <param name="password">The password to attempt to sign in with.</param>
        /// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
        /// <param name="lockoutOnFailure">Flag indicating if the user account should be locked if the sign in fails.</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
        /// for the sign-in attempt.</returns>
        public override async Task<SignInResult> PasswordSignInAsync(string userName, string password,
            bool isPersistent, bool lockoutOnFailure)
        {
            var user = await _userManager.FindByIdAsync(userName);
            if (user == null)
            {
                return SignInResult.Failed;
            }

            return await PasswordSignInAsync(user, password, isPersistent, lockoutOnFailure);
        }

        /// <summary>
        /// Attempts a password sign in for a user.
        /// </summary>
        /// <param name="user">The user to sign in.</param>
        /// <param name="password">The password to attempt to sign in with.</param>
        /// <param name="lockoutOnFailure">Flag indicating if the user account should be locked if the sign in fails. Cognito does not handle account lock out. This parameter is not used</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
        /// for the sign-in attempt.</returns>
        public override async Task<SignInResult> CheckPasswordSignInAsync(TUser user, string password, bool lockoutOnFailure)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            // Prechecks if the user password needs to be changed
            var error = await PreSignInCheck(user);
            if (error != null)
            {
                return error;
            }

            var checkPasswordResult = await _userManager.CheckPasswordAsync(user, password).ConfigureAwait(false);

            if (checkPasswordResult == null)
            {
                return SignInResult.Failed;
            }

            if (checkPasswordResult.ChallengeName == ChallengeNameType.SMS_MFA)
            {
                return SignInResult.TwoFactorRequired;
            }

            if (user.SessionTokens != null && user.SessionTokens.IsValid())
            {
                var claimsPrincipal = await _claimsFactory.CreateAsync(user).ConfigureAwait(false);
                await _contextAccessor.HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, claimsPrincipal);
                return SignInResult.Success;
            }

            return SignInResult.Failed;
        }

        /// <summary>
        /// Used to ensure that a user is allowed to sign in.
        /// </summary>
        /// <param name="user">The user</param>
        /// <returns>Null if the user should be allowed to sign in, otherwise the SignInResult why they should be denied.</returns>
        protected override async Task<SignInResult> PreSignInCheck(TUser user)
        {
            // Checks for email/phone number confirmation status
            if (!await CanSignInAsync(user))
            {
                return SignInResult.NotAllowed;
            }
            if (await IsPasswordChangeRequiredAsync(user))
            {
                return CognitoSignInResult.PasswordChangeRequired;
            }
            return null;
        }

        /// <summary>
        /// Checks if the password needs to be changed for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to check if the password needs to be changed.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if the password needs to be changed, false otherwise.</returns>
        protected async Task<bool> IsPasswordChangeRequiredAsync(TUser user)
        {
            return await _userManager.IsPasswordChangeRequiredAsync(user).ConfigureAwait(false);
        }
    }
}
