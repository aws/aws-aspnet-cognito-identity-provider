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

            MapClaimTypesToCognito(claims);

            var userNameClaimType = _identityOptions.ClaimsIdentity.UserNameClaimType;
            claims.Add(new Claim(userNameClaimType, user.Username));

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
        private void MapClaimTypesToCognito(List<Claim> claims)
        {
            var emailClaim = claims.FirstOrDefault(claim => claim.Type == CognitoAttributesConstants.Email);
            if(emailClaim != null)
                claims.Add(new Claim(ClaimTypes.Email, emailClaim.Value));

            var birthDateClaim = claims.FirstOrDefault(claim => claim.Type == CognitoAttributesConstants.BirthDate);
            if (birthDateClaim != null)
                claims.Add(new Claim(ClaimTypes.DateOfBirth, birthDateClaim.Value));

            var familyNameClaim = claims.FirstOrDefault(claim => claim.Type == CognitoAttributesConstants.FamilyName);
            if (familyNameClaim != null)
                claims.Add(new Claim(ClaimTypes.Surname, familyNameClaim.Value));

            var genderClaim = claims.FirstOrDefault(claim => claim.Type == CognitoAttributesConstants.Gender);
            if (genderClaim != null)
                claims.Add(new Claim(ClaimTypes.Gender, genderClaim.Value));

            var givenNameClaim = claims.FirstOrDefault(claim => claim.Type == CognitoAttributesConstants.GivenName);
            if (givenNameClaim != null)
                claims.Add(new Claim(ClaimTypes.GivenName, givenNameClaim.Value));

            var nameClaim = claims.FirstOrDefault(claim => claim.Type == CognitoAttributesConstants.Name);
            if (nameClaim != null)
                claims.Add(new Claim(ClaimTypes.Name, nameClaim.Value));

            var phoneNumberClaim = claims.FirstOrDefault(claim => claim.Type == CognitoAttributesConstants.PhoneNumber);
            if (phoneNumberClaim != null)
                claims.Add(new Claim(ClaimTypes.MobilePhone, phoneNumberClaim.Value));

            var websiteClaim = claims.FirstOrDefault(claim => claim.Type == CognitoAttributesConstants.Website);
            if (websiteClaim != null)
                claims.Add(new Claim(ClaimTypes.Webpage, websiteClaim.Value));
        }
    }
}
