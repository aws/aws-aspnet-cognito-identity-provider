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

using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.Cognito
{
    public partial class CognitoUserStore<TUser> : IUserEmailStore<TUser> where TUser : CognitoUser
    {
        /// <summary>
        /// Gets the user, if any, associated with the specified, normalized email address.
        /// </summary>
        /// <param name="normalizedEmail">The normalized email address to return the user for.</param>
        /// <returns>
        /// The task object containing the results of the asynchronous lookup operation, the user if any associated with the specified normalized email address.
        /// </returns>
        public async Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var result = await _cognitoClient.ListUsersAsync(new ListUsersRequest
            {
                Filter = "email = \"" + normalizedEmail + "\"",
                UserPoolId = _pool.PoolID
            }, cancellationToken).ConfigureAwait(false);

            if (result.Users.Count > 0)
            {
                return _pool.GetUser(result.Users[0].Username,
                    result.Users[0].UserStatus,
                    result.Users[0].Attributes.ToDictionary(att => att.Name, att => att.Value)) as TUser;
            }

            return null;
        }

        public async Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await GetAttributeValueAsync(user, CognitoAttributesConstants.Email, cancellationToken).ConfigureAwait(false);
        }

        public async Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return String.Equals(await GetAttributeValueAsync(user, CognitoAttributesConstants.EmailVerified, cancellationToken).ConfigureAwait(false), "true", StringComparison.InvariantCultureIgnoreCase);
        }

        public Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            throw new NotSupportedException("Cognito does not support normalized emails.");
        }

        public Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return SetAttributeValueAsync(user, CognitoAttributesConstants.Email, email, cancellationToken);
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            throw new NotSupportedException("Cognito does not allow updating the email_verified attribute. This attribute gets updated automatically upon email change or confirmation.");
        }

        public Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            throw new NotSupportedException("Cognito does not support normalized emails.");
        }
    }
}
