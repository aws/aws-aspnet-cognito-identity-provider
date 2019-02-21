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
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.Cognito
{
    /// <summary>
    /// Provides an abstraction for a store which manages Cognito accounts.
    /// This includes Cognito specific methods such has handling the auth workflow,
    /// Retrieving the user status or changing/reseting the password.
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public interface IUserCognitoStore<TUser> : IDisposable where TUser : class
    {
        /// <summary>
        /// Checks if the <param name="user"> can log in with the specified password <paramref name="password"/>.
        /// </summary>
        /// <param name="user">The user try to log in with.</param>
        /// <param name="password">The password supplied for validation.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the AuthFlowResponse object linked to that authentication workflow.</returns>
        Task<AuthFlowResponse> StartValidatePasswordAsync(TUser user, string password, CancellationToken cancellationToken);

        /// <summary>
        /// Changes the password on the cognito account associated with the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to change the password for.</param>
        /// <param name="currentPassword">The current password of the user.</param>
        /// <param name="newPassword">The new passord for the user.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if changing the password was successful, false otherwise.</returns>
        Task<IdentityResult> ChangePasswordAsync(TUser user, string currentPassword, string newPassword, CancellationToken cancellationToken);

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
        Task<IdentityResult> ChangePasswordWithTokenAsync(TUser user, string token, string newPassword, CancellationToken cancellationToken);

        /// <summary>
        /// Checks if the password needs to be changed for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to check if the password needs to be changed.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if the password needs to be changed, false otherwise.</returns>
        Task<bool> IsPasswordChangeRequiredAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// Checks if the password needs to be reset for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to check if the password needs to be reset.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if the password needs to be reset, false otherwise.</returns>
        Task<bool> IsPasswordResetRequiredAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// Resets the <paramref name="user"/>'s password and sends the confirmation token to the user 
        /// via email or sms depending on the user pool policy.
        /// </summary>
        /// <param name="user">The user to reset the password for.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if the password was reset, false otherwise.</returns>
        Task<IdentityResult> ResetPasswordAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// Registers the specified <paramref name="user"/> in Cognito with the given password,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <param name="password">The password for the user to register with</param>
        /// <param name="validationData">The validation data to be sent to the pre sign-up lambda triggers.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        Task<IdentityResult> CreateAsync(TUser user, string password, IDictionary<string, string> validationData, CancellationToken cancellationToken);

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
        Task<IEnumerable<CognitoUser>> GetUsersAsync(CognitoAttribute attributeFilterName, CognitoAttributeFilterType attributeFilterType, string attributeFilterValue, CancellationToken cancellationToken);

        /// <summary>
        /// Registers the specified <paramref name="user"/> in Cognito with the given password,
        /// as an asynchronous operation. Also submits the validation data to the pre sign-up lambda trigger.
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <param name="validationData">The validation data to be sent to the pre sign-up lambda triggers.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        Task<IdentityResult> CreateAsync(TUser user, IDictionary<string, string> validationData, CancellationToken cancellationToken);

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
        Task<IdentityResult> ConfirmSignUpAsync(TUser user, string confirmationCode, bool forcedAliasCreation, CancellationToken cancellationToken);

        /// <summary>
        /// Admin confirms the specified <paramref name="user"/>, regardless of the confirmation code
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to confirm.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        Task<IdentityResult> AdminConfirmSignUpAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// Resends the account signup confirmation code for the specified <paramref name="user"/>
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to resend the account signup confirmation code for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        Task<IdentityResult> ResendSignupConfirmationCodeAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// Generates and sends a verification code for the specified <paramref name="user"/>, 
        /// and the specified <paramref name="attributeName"/>,
        /// as an asynchronous operation.
        /// This operation requires a logged in user.
        /// </summary>
        /// <param name="user">The user to send the verification code to.</param>
        /// <param name="attributeName">The attribute to verify.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        Task<IdentityResult> GetUserAttributeVerificationCodeAsync(TUser user, string attributeName, CancellationToken cancellationToken);

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
        Task<IdentityResult> VerifyUserAttributeAsync(TUser user, string attributeName, string code, CancellationToken cancellationToken);

        /// <summary>
        /// Checks if the <param name="user"> can log in with the specified 2fa code challenge <paramref name="code"/>.
        /// </summary>
        /// <param name="user">The user try to log in with.</param>
        /// <param name="code">The 2fa code to check</param>
        /// <param name="authWorkflowSessionId">The ongoing Cognito authentication workflow id.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the AuthFlowResponse object linked to that authentication workflow.</returns>
        Task<AuthFlowResponse> RespondToTwoFactorChallengeAsync(TUser user, string code, string authWorkflowSessionId, CancellationToken cancellationToken);
    }
}