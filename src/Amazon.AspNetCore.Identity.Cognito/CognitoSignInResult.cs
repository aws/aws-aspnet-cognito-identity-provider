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

using Microsoft.AspNetCore.Identity;

namespace Amazon.AspNetCore.Identity.Cognito
{
    public class CognitoSignInResult : SignInResult
    {
        /// <summary>
        ///  Returns a CognitoSignInResult that represents a required password change.
        /// </summary>
        /// <returns>A CognitoSignInResult that represents a required password change.</returns>
        public static readonly CognitoSignInResult PasswordChangeRequired = new CognitoSignInResult { RequiresPasswordChange = true };

        /// <summary>
        ///  Returns a CognitoSignInResult that represents a required password reset.
        /// </summary>
        /// <returns>A CognitoSignInResult that represents a required password reset.</returns>
        public static readonly CognitoSignInResult PasswordResetRequired = new CognitoSignInResult { RequiresPasswordReset = true };

        /// <summary>
        ///  Returns a flag indication whether changing the password is required.
        /// </summary>
        /// <returns>A flag indication whether changing the password is required.</returns>
        public bool RequiresPasswordChange { get; protected set; }

        /// <summary>
        ///  Returns a flag indication whether reseting the password is required.
        /// </summary>
        /// <returns>A flag indication whether reseting the password is required.</returns>
        public bool RequiresPasswordReset { get; protected set; }

        /// <summary>
        /// Converts the value of the current <see cref="CognitoSignInResult"/> object to its equivalent string representation.
        /// </summary>
        /// <returns>A string representation of value of the current <see cref="CognitoSignInResult"/> object.</returns>
        public override string ToString()
        {
            return IsLockedOut ? "Lockedout" :
                   IsNotAllowed ? "NotAllowed" :
                   RequiresTwoFactor ? "RequiresTwoFactor" :
                   RequiresPasswordChange ? "RequiresPasswordChange" :
                   RequiresPasswordReset ? "RequiresPasswordReset" :
                   Succeeded ? "Succeeded" : "Failed";
        }
    }

    public static class SigninResultExtensions
    {
        public static bool IsCognitoSignInResult(this SignInResult result)
        {
            return result is CognitoSignInResult;
        }
    }
}
