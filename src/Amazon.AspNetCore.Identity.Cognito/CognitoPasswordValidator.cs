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
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.Cognito
{
    public class CognitoPasswordValidator : IPasswordValidator<CognitoUser>
    {
        // This is the list of what is considered to be a special characters by Cognito
        // See: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-policies.html
        private static readonly char[] CognitoSymbols = { '^', '$', '*', '.', '[', ']', '{', '}', '(', ')', '?', '-', '"', '!', '@', '#', '%', '&', '/', '\\', ',', '>', '<', '\'', ':', ';', '|', '_', '~', '`' };

        /// <summary>
        /// Validates a password based on a Cognito user pool password policy as an asynchronous operation.
        /// </summary>
        /// <param name="manager">The <see cref="UserManager{CognitoUser}"/> to retrieve the <paramref name="user"/> properties from.</param>
        /// <param name="user">The user whose password should be validated.</param>
        /// <param name="password">The password supplied for validation</param>
        /// <returns>The task object representing the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        public async Task<IdentityResult> ValidateAsync(UserManager<CognitoUser> manager, CognitoUser user, string password)
        {
            // Retrieve the password policy set by the user's user pool
            var passwordPolicy = await user.UserPool.GetPasswordPolicyTypeAsync().ConfigureAwait(false);

            var errorDescriber = new IdentityErrorDescriber();
            var errors = new List<IdentityError>();

            if (password.Length < passwordPolicy.MinimumLength)
            {
                errors.Add(errorDescriber.PasswordTooShort(passwordPolicy.MinimumLength));
            }

            if (!password.Any(char.IsLower) && passwordPolicy.RequireLowercase)
            {
                errors.Add(errorDescriber.PasswordRequiresLower());
            }

            if (!password.Any(char.IsUpper) && passwordPolicy.RequireUppercase)
            {
                errors.Add(errorDescriber.PasswordRequiresUpper());
            }

            if (!password.Any(char.IsNumber) && passwordPolicy.RequireNumbers)
            {
                errors.Add(errorDescriber.PasswordRequiresDigit());
            }

            var passwordContainsASymbol = password.IndexOfAny(CognitoSymbols) >= 0;
            if (!passwordContainsASymbol && passwordPolicy.RequireSymbols)
            {
                errors.Add(errorDescriber.PasswordRequiresNonAlphanumeric());
            }

            if (errors.Count > 0)
            {
                return IdentityResult.Failed(errors.ToArray());
            }
            else
            {
                return IdentityResult.Success;
            }
        }
    }
}
