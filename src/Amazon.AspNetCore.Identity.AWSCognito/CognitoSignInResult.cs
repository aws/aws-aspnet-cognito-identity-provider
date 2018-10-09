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

namespace Amazon.AspNetCore.Identity.AWSCognito
{
    public class CognitoSignInResult : SignInResult
    {
        private static readonly CognitoSignInResult _passwordChangeRequired = new CognitoSignInResult { IsPasswordChangeRequired = true };

        //
        // Summary:
        //     Returns a CognitoSignInResult that represents a required password change.
        //
        // Returns:
        //     A CognitoSignInResult that represents a required password change.
        public static CognitoSignInResult PasswordChangeRequired => _passwordChangeRequired;

        //
        // Summary:
        //     Returns a flag indication whether changing the password is required.
        public bool IsPasswordChangeRequired { get; protected set; }

        /// <summary>
        /// Converts the value of the current <see cref="CognitoSignInResult"/> object to its equivalent string representation.
        /// </summary>
        /// <returns>A string representation of value of the current <see cref="CognitoSignInResult"/> object.</returns>
        public override string ToString()
        {
            return IsLockedOut ? "Lockedout" :
                   IsNotAllowed ? "NotAllowed" :
                   RequiresTwoFactor ? "RequiresTwoFactor" :
                   IsPasswordChangeRequired ? "PasswordChangeRequired" :
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
