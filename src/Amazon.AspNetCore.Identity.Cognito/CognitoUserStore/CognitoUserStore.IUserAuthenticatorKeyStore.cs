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
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.Cognito
{
    public partial class CognitoUserStore<TUser> : IUserAuthenticatorKeyStore<TUser> where TUser : CognitoUser
    {
        public Task SetAuthenticatorKeyAsync(TUser user, string key, CancellationToken cancellationToken)
        {
            throw new NotImplementedException("Cognito doesn't support setting the authenticator key");
        }

        public async Task<string> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var request = new AssociateSoftwareTokenRequest
            {
                AccessToken = user.SessionTokens.AccessToken
            };

            try
            {
                var response = await _cognitoClient.AssociateSoftwareTokenAsync(request, cancellationToken).ConfigureAwait(false);

                return response.SecretCode;
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                throw new CognitoServiceException("Failed to retrieve Software Token key for the Cognito User", e);
            }
        }

        public async Task<bool> VerifyTwoFactorTokenAsync(TUser user, string tokenProvider, string token)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var request = new VerifySoftwareTokenRequest
            {
                UserCode = token,
                AccessToken = user.SessionTokens.AccessToken
            };

            try
            {
                var response = await _cognitoClient.VerifySoftwareTokenAsync(request).ConfigureAwait(false);

                return response.Status == VerifySoftwareTokenResponseType.SUCCESS;
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                throw new CognitoServiceException("Failed to verify Software Token for the Cognito User", e);
            }
        }
    }
}
