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

namespace Amazon.AspNetCore.Identity.AWSCognito
{
    public class CognitoStandardAttributes
    {
        // This list of default attributes follows the OpenID Connect specification.
        // Source: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html
        // Some default attributes might be required when registering a user depending on the user pool configuration.

        public const string Address = "address";
        public const string BirthDate = "birthdate";
        public const string Email = "email";
        public const string EmailVerified = "email_verified";
        public const string FamilyName = "family_name";
        public const string Gender = "gender";
        public const string GivenName = "given_name";
        public const string Locale = "locale";
        public const string MiddleName = "middle_name";
        public const string Name = "name";
        public const string NickName = "nickname";
        public const string PhoneNumber = "phone_number";
        public const string PhoneNumberVerified = "phone_number_verified";
        public const string Picture = "picture";
        public const string PreferredUsername = "preferred_username";
        public const string Profile = "profile";
        public const string ZoneInfo = "zoneinfo";
        public const string UpdatedAt = "updated_at";
        public const string Website = "website";
    }
}
