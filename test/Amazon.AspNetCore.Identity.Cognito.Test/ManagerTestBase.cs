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
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System;

namespace Amazon.AspNetCore.Identity.Cognito.Test
{
    public class ManagerTestBase
    {
        protected Mock<IHttpContextAccessor> contextAccessorMock;
        protected Mock<CognitoUserClaimsPrincipalFactory<CognitoUser>> claimsFactoryMock;
        protected Mock<IOptions<IdentityOptions>> optionsAccessorMock;
        protected Mock<ILogger<SignInManager<CognitoUser>>> loggerSigninManagerMock;
        protected Mock<IAuthenticationSchemeProvider> schemesMock;
        protected Mock<IAmazonCognitoIdentityProvider> cognitoClientMock;
        protected Mock<CognitoUserPool> cognitoPoolMock;
        protected Mock<CognitoIdentityErrorDescriber> errorsMock;
        protected Mock<CognitoUserStore<CognitoUser>> userStoreMock;
        protected Mock<IPasswordHasher<CognitoUser>> passwordHasherMock;
        protected Mock<IUserValidator<CognitoUser>> userValidatorsMock;
        protected Mock<IPasswordValidator<CognitoUser>> passwordValidatorsMock;
        protected CognitoKeyNormalizer keyNormalizer;
        protected Mock<IServiceProvider> servicesMock; 
        protected Mock<ILogger<UserManager<CognitoUser>>> loggerUserManagerMock;

        public ManagerTestBase()
        {
            cognitoClientMock = new Mock<IAmazonCognitoIdentityProvider>();
            cognitoPoolMock = new Mock<CognitoUserPool>("region_poolName", "clientID", cognitoClientMock.Object, null);
            errorsMock = new Mock<CognitoIdentityErrorDescriber>();
            optionsAccessorMock = new Mock<IOptions<IdentityOptions>>();
            var idOptions = new IdentityOptions();
            idOptions.Lockout.AllowedForNewUsers = false;
            optionsAccessorMock.Setup(o => o.Value).Returns(idOptions);
            contextAccessorMock = new Mock<IHttpContextAccessor>();
            loggerSigninManagerMock = new Mock<ILogger<SignInManager<CognitoUser>>>();
            schemesMock = new Mock<IAuthenticationSchemeProvider>();
            userStoreMock = new Mock<CognitoUserStore<CognitoUser>>(cognitoClientMock.Object, cognitoPoolMock.Object, errorsMock.Object);
            passwordHasherMock = new Mock<IPasswordHasher<CognitoUser>>();
            userValidatorsMock = new Mock<IUserValidator<CognitoUser>>();
            passwordValidatorsMock = new Mock<IPasswordValidator<CognitoUser>>();
            keyNormalizer = new CognitoKeyNormalizer();
            servicesMock = new Mock<IServiceProvider>();
            loggerUserManagerMock = new Mock<ILogger<UserManager<CognitoUser>>>();
        }

        public CognitoUser GetCognitoUser()
        {
            return new CognitoUser("userId", "clientId", cognitoPoolMock.Object, cognitoClientMock.Object);
        }
    }
}
