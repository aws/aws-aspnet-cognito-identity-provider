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
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.Cognito
{
    public class CognitoUserClaimsPrincipalFactory<TUser> : IUserClaimsPrincipalFactory<TUser> where TUser : CognitoUser
    {
        private readonly CognitoUserManager<TUser> _userManager;
        private readonly IdentityOptions _identityOptions;

        private readonly Dictionary<string, CognitoAttribute> claimToAttributesMapping = new Dictionary<string, CognitoAttribute>()
        {
            { ClaimTypes.Email, CognitoAttribute.Email },
            { ClaimTypes.DateOfBirth, CognitoAttribute.BirthDate },
            { ClaimTypes.Surname, CognitoAttribute.FamilyName },
            { ClaimTypes.Gender, CognitoAttribute.Gender },
            { ClaimTypes.GivenName, CognitoAttribute.GivenName },
            { ClaimTypes.Name, CognitoAttribute.Name },
            { ClaimTypes.MobilePhone, CognitoAttribute.PhoneNumber },
            { ClaimTypes.Webpage, CognitoAttribute.Website }
        };

        public CognitoUserClaimsPrincipalFactory(UserManager<TUser> userManager, IOptions<IdentityOptions> optionsAccessor)
        {
            _userManager = userManager as CognitoUserManager<TUser>;

            if (_userManager == null)
                throw new ArgumentNullException("The userManager must be of type CognitoUserManager<TUser>", nameof(userManager));

            if (optionsAccessor?.Value == null)
            {
                throw new ArgumentNullException(nameof(optionsAccessor));
            }

            _identityOptions = optionsAccessor.Value;
        }

        public async Task<ClaimsPrincipal> CreateAsync(TUser user)
        {
            var claims = await _userManager.GetClaimsAsync(user).ConfigureAwait(false) as List<Claim>;

            claimToAttributesMapping.ToList().ForEach(claim => MapClaimTypesToCognito(claims, claim.Key, claim.Value.AttributeName));

            claims.Add(new Claim(_identityOptions.ClaimsIdentity.UserNameClaimType, user.Username));
            claims.Add(new Claim(_identityOptions.ClaimsIdentity.UserIdClaimType, user.Username));

            var roles = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
            var roleClaimType = _identityOptions.ClaimsIdentity.RoleClaimType;
            // Roles are claims with a specific schema uri
            roles.ToList().ForEach(role => claims.Add(new Claim(roleClaimType, role)));

            var claimsIdentity = new ClaimsIdentity(claims, IdentityConstants.ApplicationScheme);
            return new ClaimsPrincipal(claimsIdentity);
        }

        /// <summary>
        /// Internal method to map System.Security.Claims.ClaimTypes to Cognito Standard Attributes
        /// </summary>
        /// <param name="claims"></param>
        private void MapClaimTypesToCognito(List<Claim> claims, string claimType, string cognitoAttribute)
        {
            var claim = claims.FirstOrDefault(c => c.Type == cognitoAttribute);
            if (claim != null)
                claims.Add(new Claim(claimType, claim.Value));
        }
    }
}
