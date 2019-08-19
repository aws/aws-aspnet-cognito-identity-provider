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
    /// <summary>
    /// Implements ILookupNormalizer by returning the key without changes as Cognito is case sensitive.
    /// For instance, a group named 'Test' is not the same as a group named 'test' in Cognito.
    /// The same is applicable to usernames.
    /// </summary>
    public class CognitoKeyNormalizer : ILookupNormalizer
    {
#if NETSTANDARD_2_0
        /// <summary>
        /// Normalizes the key to be be used by Cognito.
        /// </summary>
        /// <param name="key">The key to normalize</param>
        /// <returns></returns>
        public string Normalize(string key)
        {
            // Cognito does not handle normalization, returning the key as is.
            return key;
        }
#endif

#if NETCOREAPP_3_0
        /// <summary>
        /// Returns a normalized representation of the specified <paramref name="name"/>.
        /// </summary>
        /// <param name="name">The key to normalize.</param>
        /// <returns>A normalized representation of the specified <paramref name="name"/>.</returns>
        public string NormalizeName(string name)
        {
            // Cognito does not handle normalization, returning the name as is.
            return name;
        }

        /// <summary>
        /// Returns a normalized representation of the specified <paramref name="email"/>.
        /// </summary>
        /// <param name="email">The email to normalize.</param>
        /// <returns>A normalized representation of the specified <paramref name="email"/>.</returns>
        public string NormalizeEmail(string email)
        {
            // Cognito does not handle normalization, returning the email as is.
            return email;
        }
#endif
    }
}
