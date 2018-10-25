﻿/*
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
using System.Threading;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.AWSCognito
{
    public partial class CognitoUserStore<TUser> : IUserEmailStore<TUser> where TUser : CognitoUser
    {
        public Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            throw new NotImplementedException("Cognito does not support normalized emails.");
        }

        public async Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await GetAttributeValueAsync(user, CognitoStandardAttributes.Email, cancellationToken).ConfigureAwait(false);
        }

        public async Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await GetAttributeValueAsync(user, CognitoStandardAttributes.EmailVerified, cancellationToken).ConfigureAwait(false) == "true";
        }

        public Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException("Cognito does not support normalized emails.");
        }

        public async Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            await SetAttributeValueAsync(user, CognitoStandardAttributes.Email, email, cancellationToken).ConfigureAwait(false);
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            throw new NotImplementedException("Cognito does not allow updating the email_verified attribute. This attribute gets updated automatically upon email change or confirmation.");
        }

        public Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            throw new NotImplementedException("Cognito does not support normalized emails.");
        }
    }
}
