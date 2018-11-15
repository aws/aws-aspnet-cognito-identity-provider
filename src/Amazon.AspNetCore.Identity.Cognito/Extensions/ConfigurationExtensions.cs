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

using Amazon.AspNetCore.Identity.Cognito.Exceptions;
using Amazon.AspNetCore.Identity.Cognito.Extensions;

namespace Microsoft.Extensions.Configuration
{
    public static class ConfigurationExtensions
    {
        /// <summary>
        /// The default section where settings are read from the IConfiguration object. This is set to "AWS".
        /// </summary>
        public const string DEFAULT_CONFIG_SECTION = "AWS";

        private const string ConfigurationClientIdKey = "UserPoolClientId";
        private const string ConfigurationClientSecretKey = "UserPoolClientSecret";
        private const string ConfigurationUserPoolIdKey = "UserPoolId";

        private const string MissingKeyExceptionMessage = "The {0} key/value pair is missing or empty in the IConfiguration instance";

        /// <summary>
        /// Constructs an AWSCognitoClientOptions class with the options specifed in the "AWS" section in the IConfiguration object.
        /// </summary>
        /// <param name="config">The IConfiguration instance</param>
        /// <returns>The AWSCognitoClientOptions containing the cognito secrets.</returns>
        public static AWSCognitoClientOptions GetAWSCognitoClientOptions(this IConfiguration config)
        {
            return GetAWSCognitoClientOptions(config, DEFAULT_CONFIG_SECTION);
        }

        public static AWSCognitoClientOptions GetAWSCognitoClientOptions(this IConfiguration config, string configSection)
        {
            var options = new AWSCognitoClientOptions();

            IConfiguration section;
            if (string.IsNullOrEmpty(configSection))
                section = config;
            else
                section = config.GetSection(configSection);

            if (section == null)
                return options;

            options.UserPoolClientId = GetConfigurationValue(section, ConfigurationClientIdKey);
            options.UserPoolClientSecret = GetConfigurationValue(section, ConfigurationClientSecretKey);
            options.UserPoolId = GetConfigurationValue(section, ConfigurationUserPoolIdKey);
            
            return options;
        }

        private static string GetConfigurationValue(IConfiguration section, string configurationKey)
        {
            if (!string.IsNullOrEmpty(section[configurationKey]))
            {
                return section[configurationKey];
            }
            else
            {
                throw new CognitoConfigurationException(string.Format(MissingKeyExceptionMessage, configurationKey));
            }
        }
    }
}
