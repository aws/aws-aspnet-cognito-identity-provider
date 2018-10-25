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
    public class CognitoKeyNormalizer : ILookupNormalizer
    {
        public string Normalize(string key)
        {
            // Cognito does not handle normalization, returning the key as is.
            return key;
        }
    }
}
