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
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.Cognito
{
    public class CognitoSignInManager<TUser> : SignInManager<TUser> where TUser : CognitoUser
    {
        private readonly CognitoUserManager<TUser> _userManager;
        private readonly CognitoUserClaimsPrincipalFactory<TUser> _claimsFactory;
        private readonly IHttpContextAccessor _contextAccessor;

        private const string Cognito2FAAuthWorkflowKey = "Cognito2FAAuthWorkflowId";
        private const string Cognito2FAProviderKey = "Amazon Cognito 2FA";

#if NETCOREAPP_3_0
        public CognitoSignInManager(UserManager<TUser> userManager,
        IHttpContextAccessor contextAccessor,
        IUserClaimsPrincipalFactory<TUser> claimsFactory,
        IOptions<IdentityOptions> optionsAccessor,
        ILogger<SignInManager<TUser>> logger,
        IAuthenticationSchemeProvider schemes,
        IUserConfirmation<TUser> confirmation) : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
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
#endif
#if NETSTANDARD_2_0
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
#endif

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
            if (lockoutOnFailure)
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
        /// Attempts to sign in the specified <paramref name="user"/> and <paramref name="password"/> combination
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to sign in.</param>
        /// <param name="password">The password to attempt to sign in with.</param>
        /// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
        /// <param name="lockoutOnFailure">Cognito does not handle account lock out. This parameter must be set to false, or a NotSupportedException will be thrown.</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
        /// for the sign-in attempt.</returns>
        public override async Task<SignInResult> PasswordSignInAsync(TUser user, string password,
            bool isPersistent, bool lockoutOnFailure)
        {
            if (lockoutOnFailure)
            {
                throw new NotSupportedException("Lockout is not enabled for the CognitoUserManager.");
            }

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var attempt = await CheckPasswordSignInAsync(user, password, lockoutOnFailure).ConfigureAwait(false);
            if (attempt.Succeeded)
                await SignInAsync(user, isPersistent).ConfigureAwait(false);

            return attempt;
        }

        /// <summary>
        /// Signs in the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to sign-in.</param>
        /// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
        /// <param name="authenticationMethod">Name of the method used to authenticate the user.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public override Task SignInAsync(TUser user, bool isPersistent, string authenticationMethod = null)
        {
            // Populating the tokens to be retrieved when calling Context.GetTokenAsync(OpenIdConnectParameterNames.AccessToken).
            var authenticationProperties = new AuthenticationProperties
            {
                IsPersistent = isPersistent,
                AllowRefresh = true,
                ExpiresUtc = user.SessionTokens?.ExpirationTime,
                IssuedUtc = user.SessionTokens?.IssuedTime
            };

            AddUserTokensToAuthenticationProperties(user, authenticationProperties);

            return SignInAsync(user, authenticationProperties, authenticationMethod);
        }

        /// <summary>
        /// Adds a user tokens to the authentication properties
        /// </summary>
        /// <param name="user">The user to update tokens for</param>
        /// <param name="authenticationProperties">The authentication properties to update</param>
        private void AddUserTokensToAuthenticationProperties(TUser user, AuthenticationProperties authenticationProperties)
        {
            authenticationProperties.StoreTokens(new List<AuthenticationToken>()
            {
                new AuthenticationToken()
                {
                    Name = OpenIdConnectParameterNames.AccessToken,
                    Value = user.SessionTokens?.AccessToken
                },
                new AuthenticationToken()
                {
                    Name = OpenIdConnectParameterNames.RefreshToken,
                    Value = user.SessionTokens?.RefreshToken
                },
                new AuthenticationToken()
                {
                    Name = OpenIdConnectParameterNames.IdToken,
                    Value = user.SessionTokens?.IdToken
                }
            });
        }

        /// <summary>
        /// Regenerates the user's application cookie, whilst preserving the existing
        /// AuthenticationProperties like rememberMe, as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose sign-in cookie should be refreshed.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public override async Task RefreshSignInAsync(TUser user)
        {
            var result = await user.StartWithRefreshTokenAuthAsync(
                new InitiateRefreshTokenAuthRequest()
                {
                    AuthFlowType = AuthFlowType.REFRESH_TOKEN
                }
                ).ConfigureAwait(false);

            var auth = await Context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
            var authenticationMethod = auth?.Principal?.FindFirstValue(ClaimTypes.AuthenticationMethod);
            var properties = auth?.Properties;
            if (properties != null)
            {
                AddUserTokensToAuthenticationProperties(user, properties);
                properties.ExpiresUtc = user.SessionTokens?.ExpirationTime;
                properties.IssuedUtc = user.SessionTokens?.IssuedTime;
            }
            await SignInAsync(user, properties, authenticationMethod);
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

            // Prechecks if the user password needs to be changed or reset
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

                var userPrincipal = new ClaimsPrincipal();
                userPrincipal.AddIdentity(new ClaimsIdentity(new List<Claim>() {
                    new Claim(ClaimTypes.Name, user.UserID),
                    new Claim(Cognito2FAAuthWorkflowKey, checkPasswordResult.SessionID),
                    new Claim(ClaimTypes.AuthenticationMethod, Cognito2FAProviderKey)
                }));

                // This signs in the user in the context of 2FA only. 
                await Context.SignInAsync(IdentityConstants.TwoFactorUserIdScheme, userPrincipal).ConfigureAwait(false);
            }
            else if (user.SessionTokens != null && user.SessionTokens.IsValid())
            {
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
            if (await IsPasswordResetRequiredAsync(user).ConfigureAwait(false))
            {
                return CognitoSignInResult.PasswordResetRequired;
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

        /// <summary>
        /// Checks if the password needs to be reset for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to check if the password needs to be reset.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if the password needs to be reset, false otherwise.</returns>
        protected Task<bool> IsPasswordResetRequiredAsync(TUser user)
        {
            return _userManager.IsPasswordResetRequiredAsync(user);
        }

        /// <summary>
        /// Validates the two factor sign in code and creates and signs in the user, as an asynchronous operation.
        /// </summary>
        /// <param name="code">The two factor authentication code to validate.</param>
        /// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
        /// <param name="rememberClient">Flag indicating whether the current browser should be remember, suppressing all further 
        /// two factor authentication prompts.</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
        /// for the sign-in attempt.</returns>
        public async Task<SignInResult> RespondToTwoFactorChallengeAsync(string code, bool isPersistent, bool rememberClient)
        {
            var twoFactorInfo = await RetrieveTwoFactorInfoAsync().ConfigureAwait(false);
            if (twoFactorInfo == null ||  string.IsNullOrWhiteSpace(twoFactorInfo.UserId))
            {
                return SignInResult.Failed;
            }
            var user = await _userManager.FindByIdAsync(twoFactorInfo.UserId).ConfigureAwait(false);
            if (user == null)
            {
                return SignInResult.Failed;
            }

            // Responding to the Cognito challenge.
            await _userManager.RespondToTwoFactorChallengeAsync(user, code, twoFactorInfo.CognitoAuthenticationWorkflowId).ConfigureAwait(false);

            if (user.SessionTokens == null || !user.SessionTokens.IsValid())
            {
                return SignInResult.Failed;
            }
            else
            {
                // Cleanup external cookie
                if (twoFactorInfo.LoginProvider != null)
                {
                    await Context.SignOutAsync(IdentityConstants.ExternalScheme).ConfigureAwait(false);
                }
                // Cleanup two factor user id cookie
                await Context.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme).ConfigureAwait(false);

                if (rememberClient)
                {
                    await RememberTwoFactorClientAsync(user).ConfigureAwait(false);
                }

                // This creates the ClaimPrincipal and signs in the user in the IdentityConstants.ApplicationScheme
                await SignInAsync(user, isPersistent, twoFactorInfo.LoginProvider).ConfigureAwait(false);
                return SignInResult.Success;
            }
        }

        /// <summary>
        /// Gets the <typeparamref name="TUser"/> for the current two factor authentication login, as an asynchronous operation.
        /// </summary>
        /// <returns>The task object representing the asynchronous operation containing the <typeparamref name="TUser"/>
        /// for the sign-in attempt.</returns>
        public override async Task<TUser> GetTwoFactorAuthenticationUserAsync()
        {
            var info = await RetrieveTwoFactorInfoAsync().ConfigureAwait(false);
            if (info == null)
            {
                return null;
            }

            return await UserManager.FindByIdAsync(info.UserId).ConfigureAwait(false);
        }

        #region 2FA

        /// <summary>
        /// Retrieves the information related to the authentication workflow.
        /// </summary>
        /// <returns></returns>
        private async Task<TwoFactorAuthenticationInfo> RetrieveTwoFactorInfoAsync()
        {
            var result = await Context.AuthenticateAsync(IdentityConstants.TwoFactorUserIdScheme).ConfigureAwait(false);
            if (result?.Principal != null)
            {
                return new TwoFactorAuthenticationInfo
                {
                    UserId = result.Principal.FindFirstValue(ClaimTypes.Name),
                    LoginProvider = result.Principal.FindFirstValue(ClaimTypes.AuthenticationMethod),
                    CognitoAuthenticationWorkflowId = result.Principal.FindFirstValue(Cognito2FAAuthWorkflowKey)
                };
            }
            return null;
        }

        /// <summary>
        /// Utility class to model information related to the ongoing authentication workflow.
        /// </summary>
        internal class TwoFactorAuthenticationInfo
        {
            public string UserId { get; set; }
            public string LoginProvider { get; set; }
            public string CognitoAuthenticationWorkflowId { get; set; }
        }

        #endregion

        /// <summary>
        /// Validates the security stamp for the specified <paramref name="user"/>. Will always return false
        /// if the userManager does not support security stamps.
        /// </summary>
        /// <param name="user">The user whose stamp should be validated.</param>
        /// <param name="securityStamp">The expected security stamp value.</param>
        /// <returns>True if the stamp matches the persisted value, otherwise it will return false.</returns>
        public override async Task<bool> ValidateSecurityStampAsync(TUser user, string securityStamp)
            => user != null &&
            // Only validate the security stamp if the store supports it
            (!UserManager.SupportsUserSecurityStamp || securityStamp == await UserManager.GetSecurityStampAsync(user).ConfigureAwait(false));
        // Preventing the cookies from expiring every 30 minutes. This fix was only added to Identity 2.2.
        // https://github.com/aspnet/Identity/pull/1941

    }
}
