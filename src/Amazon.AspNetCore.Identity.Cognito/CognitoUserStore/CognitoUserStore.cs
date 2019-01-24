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
using System.Threading;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.Cognito
{
    public partial class CognitoUserStore<TUser> : IUserCognitoStore<TUser> where TUser : CognitoUser
    {
        private const string UserStatusForceChangePassword = "FORCE_CHANGE_PASSWORD";
        private const string UserStatusResetRequired = "RESET_REQUIRED";

        private IAmazonCognitoIdentityProvider _cognitoClient;
        private CognitoUserPool _pool;
        private CognitoIdentityErrorDescriber _errorDescribers;

        public CognitoUserStore(IAmazonCognitoIdentityProvider cognitoClient, CognitoUserPool pool, IdentityErrorDescriber errors)
        {
            _cognitoClient = cognitoClient ?? throw new ArgumentNullException(nameof(cognitoClient));
            _pool = pool ?? throw new ArgumentNullException(nameof(pool));
            
            // IdentityErrorDescriber provides predefined error strings such as PasswordMismatch() or InvalidUserName(String)
            // This is used when returning an instance of IdentityResult, which can be constructed with an array of errors to be surfaced to the UI.
            if (errors == null)
                throw new ArgumentNullException(nameof(errors));
            if (errors is CognitoIdentityErrorDescriber)
                _errorDescribers = errors as CognitoIdentityErrorDescriber;
            else
                throw new ArgumentException("The IdentityErrorDescriber must be of type CognitoIdentityErrorDescriber", nameof(errors));
        }

        #region IUserCognitoStore

        /// <summary>
        /// Checks if the <param name="user"> can log in with the specified password <paramref name="password"/>.
        /// </summary>
        /// <param name="user">The user try to log in with.</param>
        /// <param name="password">The password supplied for validation.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the AuthFlowResponse object linked to that authentication workflow.</returns>
        public virtual async Task<AuthFlowResponse> StartValidatePasswordAsync(TUser user, string password, CancellationToken cancellationToken)
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
        /// Checks if the <param name="user"> can log in with the specified 2fa code challenge <paramref name="code"/>.
        /// </summary>
        /// <param name="user">The user try to log in with.</param>
        /// <param name="code">The 2fa code to check</param>
        /// <param name="authWorkflowSessionId">The ongoing Cognito authentication workflow id.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the AuthFlowResponse object linked to that authentication workflow.</returns>
        public virtual async Task<AuthFlowResponse> RespondToTwoFactorChallengeAsync(TUser user, string code, string authWorkflowSessionId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                AuthFlowResponse context =
                    await user.RespondToSmsMfaAuthAsync(new RespondToSmsMfaRequest()
                    {
                        SessionID = authWorkflowSessionId,
                        MfaCode = code
                    }).ConfigureAwait(false);

                return context;
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                throw new CognitoServiceException("Failed to respond to Cognito two factor challenge.", e);
            }
        }

        /// <summary>
        /// Changes the password on the cognito account associated with the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to change the password for.</param>
        /// <param name="currentPassword">The current password of the user.</param>
        /// <param name="newPassword">The new passord for the user.</param>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        public virtual async Task<IdentityResult> ChangePasswordAsync(TUser user, string currentPassword, string newPassword, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                // We start an auth process as the user needs a valid session id to be able to change it's password.
                var authResult = await StartValidatePasswordAsync(user, currentPassword, cancellationToken).ConfigureAwait(false);
                if (authResult != null)
                {
                    if (authResult.ChallengeName == ChallengeNameType.NEW_PASSWORD_REQUIRED)
                    {
                        await user.RespondToNewPasswordRequiredAsync(new RespondToNewPasswordRequiredRequest()
                        {
                            SessionID = authResult.SessionID,
                            NewPassword = newPassword
                        }).ConfigureAwait(false);
                        return IdentityResult.Success;
                    }
                    else if (user.SessionTokens != null && user.SessionTokens.IsValid()) // User is logged in, we can change his password
                    {
                        await user.ChangePasswordAsync(currentPassword, newPassword).ConfigureAwait(false);
                        return IdentityResult.Success;
                    }
                    else
                        return IdentityResult.Failed(_errorDescribers.PasswordMismatch());
                }
                else
                    return IdentityResult.Failed(_errorDescribers.PasswordMismatch());
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                return IdentityResult.Failed(_errorDescribers.CognitoServiceError("Failed to change the Cognito User password", e));
            }
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
        public virtual async Task<IdentityResult> ChangePasswordWithTokenAsync(TUser user, string token, string newPassword, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                await _pool.ConfirmForgotPassword(user.Username, token, newPassword, cancellationToken).ConfigureAwait(false);
                return IdentityResult.Success;
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                return IdentityResult.Failed(_errorDescribers.CognitoServiceError("Failed to change the Cognito User password", e));
            }
        }

        /// <summary>
        /// Checks if the password needs to be changed for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to check if the password needs to be changed.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if the password needs to be changed, false otherwise.</returns>
        public virtual Task<bool> IsPasswordChangeRequiredAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            bool IsPasswordChangeRequired = user.Status.Equals(UserStatusForceChangePassword, StringComparison.InvariantCulture);
            return Task.FromResult(IsPasswordChangeRequired);
        }

        /// <summary>
        /// Checks if the password needs to be reset for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to check if the password needs to be reset.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if the password needs to be reset, false otherwise.</returns>
        public virtual Task<bool> IsPasswordResetRequiredAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            bool IsPasswordResetRequired = user.Status.Equals(UserStatusResetRequired, StringComparison.InvariantCulture);
            return Task.FromResult(IsPasswordResetRequired);
        }

        /// <summary>
        /// Resets the <paramref name="user"/>'s password and sends the confirmation token to the user 
        /// via email or sms depending on the user pool policy.
        /// </summary>
        /// <param name="user">The user to reset the password for.</param>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        public virtual async Task<IdentityResult> ResetPasswordAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var request = new AdminResetUserPasswordRequest
            {
                Username = user.Username,
                UserPoolId = _pool.PoolID
            };

            try
            {
                await _cognitoClient.AdminResetUserPasswordAsync(request, cancellationToken).ConfigureAwait(false);

                return IdentityResult.Success;
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                return IdentityResult.Failed(_errorDescribers.CognitoServiceError("Failed to reset the Cognito User password", e));
            }
        }

        /// <summary>
        /// Registers the specified <paramref name="user"/> in Cognito with the given password,
        /// as an asynchronous operation. Also submits the validation data to the pre sign-up lambda trigger.
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <param name="password">The password for the user to register with</param>
        /// <param name="validationData">The validation data to be sent to the pre sign-up lambda triggers.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> CreateAsync(TUser user, string password, IDictionary<string, string> validationData, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                await _pool.SignUpAsync(user.UserID, password, user.Attributes, validationData).ConfigureAwait(false);
                return IdentityResult.Success;
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                return IdentityResult.Failed(_errorDescribers.CognitoServiceError("Failed to create the Cognito User", e));
            }
        }

        /// <summary>
        /// Confirms the specified <paramref name="user"/> with the specified
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
        public virtual async Task<IdentityResult> ConfirmSignUpAsync(TUser user, string confirmationCode, bool forcedAliasCreation, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                await user.ConfirmSignUpAsync(confirmationCode, forcedAliasCreation).ConfigureAwait(false);
                return IdentityResult.Success;
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                return IdentityResult.Failed(_errorDescribers.CognitoServiceError("Failed to confirm the Cognito User signup", e));
            }
        }

        /// <summary>
        /// Admin confirms the specified <paramref name="user"/>, regardless of the confirmation code
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to confirm.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> AdminConfirmSignUpAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                await _cognitoClient.AdminConfirmSignUpAsync(new AdminConfirmSignUpRequest
                {
                    Username = user.Username,
                    UserPoolId = _pool.PoolID
                }, cancellationToken).ConfigureAwait(false);
                return IdentityResult.Success;
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                return IdentityResult.Failed(_errorDescribers.CognitoServiceError("Failed to admin confirm the Cognito User signup", e));
            }
        }

        /// <summary>
        /// Generates and sends a verification code for the specified <paramref name="user"/>, 
        /// and the specified <paramref name="attributeName"/>,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to send the verification code to.</param>
        /// <param name="attributeName">The attribute to verify.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> GetUserAttributeVerificationCodeAsync(TUser user, string attributeName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if(attributeName != CognitoAttributesConstants.PhoneNumber && attributeName != CognitoAttributesConstants.Email)
            {
                throw new ArgumentException(string.Format("Invalid attribute name, only {0} and {1} can be verified", CognitoAttributesConstants.PhoneNumber, CognitoAttributesConstants.Email), nameof(attributeName));
            }

            try
            {
                await _cognitoClient.GetUserAttributeVerificationCodeAsync(new GetUserAttributeVerificationCodeRequest
                {
                    AccessToken = user.SessionTokens.AccessToken,
                    AttributeName = attributeName
                }, cancellationToken).ConfigureAwait(false);
                return IdentityResult.Success;
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                return IdentityResult.Failed(_errorDescribers.CognitoServiceError("Failed to get the Cognito User attribute verification code", e));
            }
        }

        /// <summary>
        /// Verifies the confirmation <paramref name="code"/> for the specified <paramref name="user"/>, 
        /// and the specified <paramref name="attributeName"/>,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to verify the code for.</param>
        /// <param name="attributeName">The attribute to verify.</param>
        /// <param name="code">The verification code to check.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> VerifyUserAttributeAsync(TUser user, string attributeName, string code, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (attributeName != CognitoAttributesConstants.PhoneNumber && attributeName != CognitoAttributesConstants.Email)
            {
                throw new ArgumentException(string.Format("Invalid attribute name, only {0} and {1} can be verified", CognitoAttributesConstants.PhoneNumber, CognitoAttributesConstants.Email), nameof(attributeName));
            }

            try
            {
                await _cognitoClient.VerifyUserAttributeAsync(new VerifyUserAttributeRequest
                {
                    AccessToken = user.SessionTokens.AccessToken,
                    AttributeName = attributeName,
                    Code = code
                }, cancellationToken).ConfigureAwait(false);
                return IdentityResult.Success;
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                return IdentityResult.Failed(_errorDescribers.CognitoServiceError("Failed to verify the attribute for the Cognito User", e));
            }
        }

        /// <summary>
        /// Internal method to get a user attribute value, while checking if this attribute is readable
        /// </summary>
        /// <param name="user">The user to retrieve the attribute for.</param>
        /// <param name="attributeName">The attribute to retrieve.</param>
        /// <returns></returns>
        private async Task<string> GetAttributeValueAsync(TUser user, string attributeName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user.Attributes == null)
            {
                throw new ArgumentException("user.Attributes must be initialized.");
            }

            var clientConfig = await _pool.GetUserPoolClientConfiguration().ConfigureAwait(false);
            if (!clientConfig.ReadAttributes.Contains(attributeName))
            {
                throw new NotAuthorizedException(string.Format("Reading attribute {0} is not allowed by the user pool client configuration.", attributeName));
            }

            // There is an edge case where an attribute might be there in the pool configuration, but not on the user profile
            if (user.Attributes.ContainsKey(attributeName))
            {
                return user.Attributes[attributeName];
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Internal method to get a user attribute value, while checking if this attribute is settable.
        /// </summary>
        /// <param name="user">The user to set the attribute for.</param>
        /// <param name="attributeName">The attribute name.</param>
        /// <param name="attributeValue">The new attribute value.</param>
        /// <returns></returns>
        private async Task SetAttributeValueAsync(TUser user, string attributeName, string attributeValue, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user.Attributes == null)
            {
                throw new ArgumentException("user.Attributes must be initialized.");
            }

            var clientConfig = await _pool.GetUserPoolClientConfiguration().ConfigureAwait(false);

            if (!clientConfig.WriteAttributes.Contains(attributeName))
            {
                throw new NotAuthorizedException(string.Format("Writing to attribute {0} is not allowed by the user pool client configuration.", attributeName));
            }

            user.Attributes[attributeName] = attributeValue;
        }

        #endregion

        #region IDisposable
        private bool disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (disposed)
                return;

            disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}
