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

using Amazon.CognitoIdentityProvider;
using Microsoft.AspNetCore.Identity;
using System;

namespace Amazon.AspNetCore.Identity.Cognito.Exceptions
{
    /// <summary>
    /// Service to enable Cognito specific errors for application facing identity errors.
    /// </summary>
    /// <remarks>
    /// These errors are returned to controllers and are generally used as display messages to end users.
    /// </remarks>
    public class CognitoIdentityErrorDescriber : IdentityErrorDescriber
    {
        /// <summary>
        /// Returns the <see cref="IdentityError"/> indicating a CognitoServiceError.
        /// </summary>
        /// <param name="failingOperationMessage">The message related to the operation that failed</param>
        /// <param name="exception">The exception</param>
        /// <returns>The default <see cref="IdentityError"/>.</returns>
        public IdentityError CognitoServiceError(string failingOperationMessage, AmazonCognitoIdentityProviderException exception)
        {
            return new IdentityError
            {
                Code = nameof(CognitoServiceError),
                Description = String.Format("{0} : {1}", failingOperationMessage, exception.Message)
            };
        }
    }
}
