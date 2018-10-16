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
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.AWSCognito
{
    /// <summary>
    /// Provides an abstraction for a store which manages Cognito accounts.
    /// This includes Cognito specific methods such has handling the auth workflow,
    /// Retrieving the user status or changing/reseting the password.
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    interface IUserCognitoStore<TUser> : IDisposable where TUser : class
    {
        /// <summary>
        /// Checks if the <param name="user"> can log in with the specified password <paramref name="password"/>.
        /// </summary>
        /// <param name="user">The user try to log in with.</param>
        /// <param name="password">The password supplied for validation.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the AuthFlowResponse object linked to that authentication workflow.</returns>
        Task<AuthFlowResponse> StartValidatePasswordAsync(TUser user, string password, CancellationToken cancellationToken);

        /// <summary>
        /// Changes the passowrd on the cognito account associated with the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to change the password for.</param>
        /// <param name="currentPassword">The current password of the user.</param>
        /// <param name="newPassword">The new passord for the user.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if changing the password was successful, false otherwise.</returns>
        Task<bool> ChangePasswordAsync(TUser user, string currentPassword, string newPassword, CancellationToken cancellationToken);

        /// <summary>
        /// Checks if the password needs to be changed for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to check if the password needs to be changed.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if the password needs to be changed, false otherwise.</returns>
        Task<bool> IsPasswordChangeRequiredAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// Resets the password for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to reset the password for.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a boolean set to true if the password was reset, false otherwise.</returns>
        Task<bool> ResetUserPasswordAsync(TUser user, CancellationToken cancellationToken);

    }
}
