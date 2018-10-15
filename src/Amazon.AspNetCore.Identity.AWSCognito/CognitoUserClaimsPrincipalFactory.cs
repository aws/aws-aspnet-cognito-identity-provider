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
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.AWSCognito
{
    public class CognitoUserClaimsPrincipalFactory<TUser> : IUserClaimsPrincipalFactory<TUser> where TUser : CognitoUser
    {
        private readonly IUserClaimStore<TUser> _userClaimStore;
        public CognitoUserClaimsPrincipalFactory(IUserClaimStore<TUser> userClaimStore)
        {
            _userClaimStore = userClaimStore ?? throw new ArgumentNullException(nameof(userClaimStore));
        }

        public async Task<ClaimsPrincipal> CreateAsync(TUser user)
        {
            var claims = await _userClaimStore.GetClaimsAsync(user, CancellationToken.None).ConfigureAwait(false) as List<Claim>;
            claims.Add(new Claim(ClaimTypes.Name, user.Username));
            // TODO: Additional claim mapping needs to be designed
            var claimsIdentity = new ClaimsIdentity(claims, IdentityConstants.ApplicationScheme);
            return new ClaimsPrincipal(claimsIdentity);
        }
    }
}
