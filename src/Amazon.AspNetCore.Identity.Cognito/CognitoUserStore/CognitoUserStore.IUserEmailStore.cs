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
        public virtual async Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
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
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                throw new CognitoServiceException("Failed to find the Cognito User by email", e);
            }

            return null;
        }

        public virtual async Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await GetAttributeValueAsync(user, CognitoAttribute.Email.AttributeName, cancellationToken).ConfigureAwait(false);
        }

        public virtual async Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return String.Equals(await GetAttributeValueAsync(user, CognitoAttribute.EmailVerified.AttributeName, cancellationToken).ConfigureAwait(false), "true", StringComparison.InvariantCultureIgnoreCase);
        }

        public Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            throw new NotSupportedException("Cognito does not support normalized emails.");
        }

        public virtual Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return SetAttributeValueAsync(user, CognitoAttribute.Email.AttributeName, email, cancellationToken);
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
