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

        public CognitoSignInManager(UserManager<TUser> userManager, 
            IHttpContextAccessor contextAccessor, 
            IUserClaimsPrincipalFactory<TUser> claimsFactory, 
            IOptions<IdentityOptions> optionsAccessor, 
            ILogger<SignInManager<TUser>> logger,
            IAuthenticationSchemeProvider schemes) : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes)
        {

            if (userManager == null)
                throw new ArgumentNullException(nameof(userManager));
            if (claimsFactory == null)
                throw new ArgumentNullException(nameof(claimsFactory));

            if (userManager is CognitoUserManager<TUser>)
                _userManager = userManager as CognitoUserManager<TUser>;
            else
                throw new ArgumentException("The userManager must be of type CognitoUserManager<TUser>", nameof(userManager));

            if (claimsFactory is CognitoUserClaimsPrincipalFactory<TUser>)
                _claimsFactory = claimsFactory as CognitoUserClaimsPrincipalFactory<TUser>;
            else
                throw new ArgumentException("The claimsFactory must be of type CognitoUserClaimsPrincipalFactory<TUser>", nameof(claimsFactory));

            _contextAccessor = contextAccessor ?? throw new ArgumentNullException(nameof(contextAccessor));
        }

        /// <summary>
        /// Attempts to sign in the specified <paramref name="userId"/> and <paramref name="password"/> combination
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="userId">The user id to sign in with. This can be a username, an email, or a phone number depending on the user pool policy.</param>
        /// <param name="password">The password to attempt to sign in with.</param>
        /// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
        /// <param name="lockoutOnFailure">Cognito does not handle account lock out. This parameter must be set to false, or a NotSupportedException will be thrown.</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
        /// for the sign-in attempt.</returns>
        public override async Task<SignInResult> PasswordSignInAsync(string userId, string password,
            bool isPersistent, bool lockoutOnFailure)
        {
            if(lockoutOnFailure)
            {
                throw new NotSupportedException("Lockout is not enabled for the CognitoUserManager.");
            }

            var user = await _userManager.FindByIdAsync(userId).ConfigureAwait(false);
            if (user == null)
            {
                return SignInResult.Failed;
            }

            return await PasswordSignInAsync(user, password, isPersistent, lockoutOnFailure).ConfigureAwait(false);
        }

        /// <summary>
        /// Attempts a password sign in for a user.
        /// </summary>
        /// <param name="user">The user to sign in.</param>
        /// <param name="password">The password to attempt to sign in with.</param>
        /// <param name="lockoutOnFailure">Cognito does not handle account lock out. This parameter must be set to false, or a NotSupportedException will be thrown.</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
        /// for the sign-in attempt.</returns>
        public override async Task<SignInResult> CheckPasswordSignInAsync(TUser user, string password, bool lockoutOnFailure)
        {
            if (lockoutOnFailure)
            {
                throw new NotSupportedException("Lockout is not enabled for the CognitoUserManager.");
            }

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            // Prechecks if the user password needs to be changed
            var error = await PreSignInCheck(user).ConfigureAwait(false);
            if (error != null)
            {
                return error;
            }

            var checkPasswordResult = await _userManager.CheckPasswordAsync(user, password).ConfigureAwait(false);

            SignInResult signinResult;

            if (checkPasswordResult == null)
            {
                signinResult = SignInResult.Failed;
            }
            else if (checkPasswordResult.ChallengeName == ChallengeNameType.SMS_MFA)
            {
                signinResult = SignInResult.TwoFactorRequired;
            }
            else if (user.SessionTokens != null && user.SessionTokens.IsValid())
            {
                var claimsPrincipal = await _claimsFactory.CreateAsync(user).ConfigureAwait(false);
                await _contextAccessor.HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, claimsPrincipal).ConfigureAwait(false);
                signinResult = SignInResult.Success;
            }
            else
            {
                signinResult = SignInResult.Failed;
            }

            return signinResult;
        }

        /// <summary>
        /// Used to ensure that a user is allowed to sign in.
        /// </summary>
        /// <param name="user">The user</param>
        /// <returns>Null if the user should be allowed to sign in, otherwise the SignInResult why they should be denied.</returns>
        protected override async Task<SignInResult> PreSignInCheck(TUser user)
        {
            // Checks for email/phone number confirmation status
            if (!await CanSignInAsync(user).ConfigureAwait(false))
            {
                return SignInResult.NotAllowed;
            }
            if (await IsPasswordChangeRequiredAsync(user).ConfigureAwait(false))
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
        protected Task<bool> IsPasswordChangeRequiredAsync(TUser user)
        {
            return _userManager.IsPasswordChangeRequiredAsync(user);
        }
    }
}
