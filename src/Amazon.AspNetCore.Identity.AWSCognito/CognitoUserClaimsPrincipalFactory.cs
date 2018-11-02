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
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.AWSCognito
{
    public class CognitoUserClaimsPrincipalFactory<TUser> : IUserClaimsPrincipalFactory<TUser> where TUser : CognitoUser
    {
        private readonly CognitoUserManager<TUser> _userManager;
        private readonly IdentityOptions _identityOptions;

        public CognitoUserClaimsPrincipalFactory(UserManager<TUser> userManager, IOptions<IdentityOptions> optionsAccessor)
        {
            _userManager = userManager as CognitoUserManager<TUser>;

            if (_userManager == null)
                throw new ArgumentNullException("The userManager must be of type CognitoUserManager<TUser>", nameof(userManager));

            if (optionsAccessor == null || optionsAccessor.Value == null)
            {
                throw new ArgumentNullException(nameof(optionsAccessor));
            }

            _identityOptions = optionsAccessor.Value;
        }

        public async Task<ClaimsPrincipal> CreateAsync(TUser user)
        {
            var claims = await _userManager.GetClaimsAsync(user).ConfigureAwait(false) as List<Claim>;
            // TODO: Additional claim mapping needs to be designed

            var userNameClaimType = _identityOptions.ClaimsIdentity.UserNameClaimType;
            claims.Add(new Claim(userNameClaimType, user.Username));

            var roles = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
            var roleClaimType = _identityOptions.ClaimsIdentity.RoleClaimType;
            // Roles are claims with a specific schema uri
            roles.ToList().ForEach(role => claims.Add(new Claim(roleClaimType, role)));

            var claimsIdentity = new ClaimsIdentity(claims, IdentityConstants.ApplicationScheme);
            return new ClaimsPrincipal(claimsIdentity);
        }
    }
}
