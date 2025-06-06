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

using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Moq;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace Amazon.AspNetCore.Identity.Cognito.Tests
{
    public class CognitoSigninManagerTests : ManagerTestBase
    {
        private CognitoSignInManager<CognitoUser> signinManager;
        private Mock<CognitoUserManager<CognitoUser>> userManagerMock;

        public CognitoSigninManagerTests() : base()
        {
            userManagerMock = new Mock<CognitoUserManager<CognitoUser>>(userStoreMock.Object, null, null, null, null, null, null, null, null, contextAccessorMock.Object);
            claimsFactoryMock = new Mock<CognitoUserClaimsPrincipalFactory<CognitoUser>>(userManagerMock.Object, optionsAccessorMock.Object);
            signinManager = new CognitoSignInManager<CognitoUser>(userManagerMock.Object, contextAccessorMock.Object, claimsFactoryMock.Object, optionsAccessorMock.Object, loggerSigninManagerMock.Object, schemesMock.Object, userConfirmationMock.Object);
        }

        [Fact]
        public async Task Test_GivenAnUnknownUser_WhenPasswordSignIn_ThenReturnSigninResultFailed()
        {
            var signinResult = SignInResult.Failed;
            CognitoUser user = null;
            userManagerMock.Setup(mock => mock.FindByIdAsync(It.IsAny<string>())).Returns(Task.FromResult(user)).Verifiable();
            var output = await signinManager.PasswordSignInAsync("userId", "password", true, false);
            Assert.Equal(signinResult, output);
            userManagerMock.Verify();
        }
        
        [Fact]
        public async Task Test_GivenAUserWithWrongPassword_WhenPasswordSignIn_ThenReturnSigninResultFailed()
        {
            AuthFlowResponse authFlowResponse = null;
            bool isPasswordChangeRequired = false;
            var signinResult = SignInResult.Failed;
            userManagerMock.Setup(mock => mock.FindByIdAsync(It.IsAny<string>())).Returns(Task.FromResult(GetCognitoUser())).Verifiable();
            userManagerMock.Setup(mock => mock.CheckPasswordAsync(It.IsAny<CognitoUser>(), It.IsAny<string>())).Returns(Task.FromResult(authFlowResponse)).Verifiable();
            userManagerMock.Setup(mock => mock.IsPasswordChangeRequiredAsync(It.IsAny<CognitoUser>())).Returns(Task.FromResult(isPasswordChangeRequired)).Verifiable();
            var output = await signinManager.PasswordSignInAsync("userId", "password", true, false);
            Assert.Equal(signinResult, output);
            userManagerMock.Verify();
        }

        [Fact]
        public async Task Test_GivenAUserWithNo2FA_WhenPasswordSignIn_ThenReturnSigninResultSuccess()
        {
            var cognitoUser = GetCognitoUser();
            var authFlowResponse = new AuthFlowResponse("sessionId", null, null, null, null);
            bool isPasswordChangeRequired = false;
            var signinResult = SignInResult.Success;

            userManagerMock.Setup(mock => mock.FindByIdAsync(It.IsAny<string>())).Returns(Task.FromResult(cognitoUser)).Verifiable();
            userManagerMock.Setup(mock => mock.IsPasswordChangeRequiredAsync(It.IsAny<CognitoUser>())).Returns(Task.FromResult(isPasswordChangeRequired)).Verifiable();
            userManagerMock.Setup(mock => mock.CheckPasswordAsync(It.IsAny<CognitoUser>(), It.IsAny<string>()))
                .Returns(Task.FromResult(authFlowResponse))
                .Callback(() => cognitoUser.SessionTokens = new CognitoUserSession("idToken", "accessToken", "refreshToken", DateTime.Now, DateTime.Now.AddDays(1))).Verifiable();
            userManagerMock.Setup(mock => mock.GetClaimsAsync(It.IsAny<CognitoUser>())).Returns(Task.FromResult(new List<Claim>() as IList<Claim>)).Verifiable();
            userManagerMock.Setup(mock => mock.GetRolesAsync(It.IsAny<CognitoUser>())).Returns(Task.FromResult(new List<string>() as IList<string>)).Verifiable();

            var context = MockUtils.MockContext(cognitoUser, IdentityConstants.TwoFactorUserIdScheme);
            contextAccessorMock.Setup(a => a.HttpContext).Returns(context).Verifiable();

            var output = await signinManager.PasswordSignInAsync("userId", "password", true, false);

            Assert.Equal(signinResult, output);
            userManagerMock.Verify();
            contextAccessorMock.Verify();
        }

        [Fact]
        public async Task Test_GivenAUserWithPasswordChangeRequired_WhenPasswordSignIn_ThenReturnSigninResultPassowrdChangeRequired()
        {
            bool isPasswordChangeRequired = true;
            var signinResult = CognitoSignInResult.PasswordChangeRequired;

            userManagerMock.Setup(mock => mock.FindByIdAsync(It.IsAny<string>())).Returns(Task.FromResult(GetCognitoUser())).Verifiable();
            userManagerMock.Setup(mock => mock.IsPasswordChangeRequiredAsync(It.IsAny<CognitoUser>())).Returns(Task.FromResult(isPasswordChangeRequired)).Verifiable();

            var output = await signinManager.PasswordSignInAsync("userId", "password", true, false);
            Assert.Equal(signinResult, output);
            userManagerMock.Verify();
        }

        [Fact]
        public async Task Test_GivenAUserWithPasswordResetRequired_WhenPasswordSignIn_ThenReturnSigninResultPassowrdResetRequired()
        {
            bool isPasswordResetRequired = true;
            var signinResult = CognitoSignInResult.PasswordResetRequired;

            userManagerMock.Setup(mock => mock.FindByIdAsync(It.IsAny<string>())).Returns(Task.FromResult(GetCognitoUser())).Verifiable();
            userManagerMock.Setup(mock => mock.IsPasswordResetRequiredAsync(It.IsAny<CognitoUser>())).Returns(Task.FromResult(isPasswordResetRequired)).Verifiable();

            var output = await signinManager.PasswordSignInAsync("userId", "password", true, false);
            Assert.Equal(signinResult, output);
            userManagerMock.Verify();
        }

        [Fact]
        public async Task Test_GivenAUserWith2FA_WhenPasswordSignIn_ThenReturnSigninResultTwoFactorRequired()
        {
            var cognitoUser = GetCognitoUser();
            bool isPasswordChangeRequired = false;
            var signinResult = SignInResult.TwoFactorRequired;
            var authFlowResponse = new AuthFlowResponse("2FASESSIONID", null, ChallengeNameType.SMS_MFA, null, null);

            userManagerMock.Setup(mock => mock.FindByIdAsync(It.IsAny<string>())).Returns(Task.FromResult(cognitoUser));
            userManagerMock.Setup(mock => mock.CheckPasswordAsync(It.IsAny<CognitoUser>(), It.IsAny<string>())).Returns(Task.FromResult(authFlowResponse));
            userManagerMock.Setup(mock => mock.IsPasswordChangeRequiredAsync(It.IsAny<CognitoUser>())).Returns(Task.FromResult(isPasswordChangeRequired));

            var context = MockUtils.MockContext(cognitoUser, IdentityConstants.TwoFactorUserIdScheme);
            contextAccessorMock.Setup(a => a.HttpContext).Returns(context).Verifiable();

            var output = await signinManager.PasswordSignInAsync("userId", "password", true, false);

            Assert.Equal(signinResult, output);
            contextAccessorMock.Verify();
        }

        [Fact]
        public async Task Test_GivenAUserWith2FA_WhenRespondToTwoFactorChallengeWithCorrectCode_ThenReturnSigninResultSuccess()
        {
            var cognitoUser = GetCognitoUser();
            var context = MockUtils.MockContext(cognitoUser, IdentityConstants.TwoFactorUserIdScheme);
            contextAccessorMock.Setup(a => a.HttpContext).Returns(context).Verifiable();

            var authFlowResponse = new AuthFlowResponse("sessionId", null, ChallengeNameType.SMS_MFA, null, null);

            userManagerMock.Setup(mock => mock.FindByIdAsync(It.IsAny<string>())).Returns(Task.FromResult(cognitoUser)).Verifiable();
            userManagerMock.Setup(mock => mock.RespondToTwoFactorChallengeAsync(It.IsAny<CognitoUser>(), It.IsAny<string>(), It.IsAny<ChallengeNameType>(), It.IsAny<string>()))
                .Returns(Task.FromResult(authFlowResponse))
                .Callback(() => cognitoUser.SessionTokens = new CognitoUserSession("idToken", "accessToken", "refreshToken", DateTime.Now, DateTime.Now.AddDays(1))).Verifiable();
            userManagerMock.Setup(mock => mock.GetClaimsAsync(It.IsAny<CognitoUser>())).Returns(Task.FromResult(new List<Claim>() as IList<Claim>)).Verifiable();
            userManagerMock.Setup(mock => mock.GetRolesAsync(It.IsAny<CognitoUser>())).Returns(Task.FromResult(new List<string>() as IList<string>)).Verifiable();

            var output = await signinManager.RespondToTwoFactorChallengeAsync("2FACODE", true, false);

            Assert.Equal(SignInResult.Success, output);
            contextAccessorMock.Verify();
            userManagerMock.Verify();
        }

        [Fact]
        public async Task Test_GivenAUserWith2FA_WhenRespondToTwoFactorChallengeWithWrongCode_ThenReturnSigninResultFailed()
        {
            var cognitoUser = GetCognitoUser();
            var context = MockUtils.MockContext(cognitoUser, IdentityConstants.TwoFactorUserIdScheme);
            contextAccessorMock.Setup(a => a.HttpContext).Returns(context).Verifiable();

            AuthFlowResponse authFlowResponse = null;

            userManagerMock.Setup(mock => mock.FindByIdAsync(It.IsAny<string>())).Returns(Task.FromResult(cognitoUser)).Verifiable();
            userManagerMock.Setup(mock => mock.RespondToTwoFactorChallengeAsync(It.IsAny<CognitoUser>(), It.IsAny<string>(), It.IsAny<ChallengeNameType>(), It.IsAny<string>()))
                .Returns(Task.FromResult(authFlowResponse)).Verifiable();

            var output = await signinManager.RespondToTwoFactorChallengeAsync("2FACODE", true, false);

            Assert.Equal(SignInResult.Failed, output);
            contextAccessorMock.Verify();
            userManagerMock.Verify();
        }


        [Fact]
        public async Task Test_GivenAUserSignedInWith2FAContext_WhenGetTwoFactorAuthenticationUser_ThenTheUserIsRetrieved()
        {
            var cognitoUser = GetCognitoUser();

            var context = MockUtils.MockContext(cognitoUser, IdentityConstants.TwoFactorUserIdScheme);
            contextAccessorMock.Setup(a => a.HttpContext).Returns(context).Verifiable();
            userManagerMock.Setup(mock => mock.FindByIdAsync(It.IsAny<string>())).Returns(Task.FromResult(cognitoUser)).Verifiable();

            var output = await signinManager.GetTwoFactorAuthenticationUserAsync();

            Assert.Equal(cognitoUser, output);
            contextAccessorMock.Verify();
            userManagerMock.Verify();
        }

        #region ExceptionTests
        [Fact]
        public async Task Test_GivenUserIdAndLockoutActivated_WhenPasswordSignIn_ThenThrowsNotSupportedException()
        {
            var ex = await Assert.ThrowsAsync<NotSupportedException>(() => signinManager.PasswordSignInAsync("userId", "password", true, lockoutOnFailure: true));
            Assert.Equal("Lockout is not enabled for the CognitoUserManager.", ex.Message);
        }

        [Fact]
        public async Task Test_GivenUserAndLockoutActivated_WhenPasswordSignIn_ThenThrowsNotSupportedException()
        {
            var cognitoUser = new CognitoUser("userId", "clientId", cognitoPoolMock.Object, cognitoClientMock.Object);
            var ex = await Assert.ThrowsAsync<NotSupportedException>(() => signinManager.PasswordSignInAsync(cognitoUser, "password", true, lockoutOnFailure: true));
            Assert.Equal("Lockout is not enabled for the CognitoUserManager.", ex.Message);
        }

        [Fact]
        public async Task Test_GivenUserAndLockoutActivated_WhenCheckPasswordSignIn_ThenThrowsNotSupportedException()
        {
            var cognitoUser = new CognitoUser("userId", "clientId", cognitoPoolMock.Object, cognitoClientMock.Object);
            var ex = await Assert.ThrowsAsync<NotSupportedException>(() => signinManager.CheckPasswordSignInAsync(cognitoUser, "password", lockoutOnFailure: true));
            Assert.Equal("Lockout is not enabled for the CognitoUserManager.", ex.Message);
        }

        [Fact]
        public async Task Test_GivenNullUser_WhenCheckPasswordSignIn_ThenThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => signinManager.CheckPasswordSignInAsync(null, "password", false));
        }

        [Fact]
        public async Task Test_GivenNullUser_WhenPasswordSignIn_ThenThrowsArgumentNullException()
        {
            CognitoUser user = null;
            await Assert.ThrowsAsync<ArgumentNullException>(() => signinManager.PasswordSignInAsync(user, "password", false, false));
        }
        #endregion
    }
}
