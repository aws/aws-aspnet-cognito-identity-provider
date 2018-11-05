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

namespace Amazon.AspNetCore.Identity.AWSCognito.Extensions
{
    public class AWSCognitoClientOptions
    {
        /// <summary>
        /// The User Pool client id.
        /// </summary>
        public string UserPoolClientId { get; set; }

        /// <summary>
        /// The User Pool client secret associated with the client id.
        /// </summary>
        public string UserPoolClientSecret { get; set; }

        /// <summary>
        /// The User Pool id associated with the client id.
        /// </summary>
        public string UserPoolId { get; set; }
    }
}
