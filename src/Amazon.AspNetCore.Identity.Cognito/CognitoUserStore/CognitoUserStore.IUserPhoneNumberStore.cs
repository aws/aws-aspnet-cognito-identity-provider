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
using System.Threading;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.Cognito
{
    public partial class CognitoUserStore<TUser> : IUserPhoneNumberStore<TUser> where TUser : CognitoUser
    {
        public virtual async Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await GetAttributeValueAsync(user, CognitoAttribute.PhoneNumber.AttributeName, cancellationToken).ConfigureAwait(false);
        }

        public virtual async Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return String.Equals(await GetAttributeValueAsync(user, CognitoAttribute.PhoneNumberVerified.AttributeName, cancellationToken).ConfigureAwait(false), "true", StringComparison.InvariantCultureIgnoreCase);
        }

        public virtual Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return SetAttributeValueAsync(user, CognitoAttribute.PhoneNumber.AttributeName, phoneNumber, cancellationToken);
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            throw new NotSupportedException("Cognito does not allow updating the phone_verified attribute. This attribute gets updated automatically upon phone number change or confirmation.");
        }
    }
}
