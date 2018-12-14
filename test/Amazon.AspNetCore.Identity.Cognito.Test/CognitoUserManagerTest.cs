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

using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Moq;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Amazon.AspNetCore.Identity.Cognito.Test
{
    public class CognitoUserManagerTest : ManagerTestBase
    {
        private CognitoUserManager<CognitoUser> userManager;
        

        public CognitoUserManagerTest() : base()
        {
            

            userManager = new CognitoUserManager<CognitoUser>(userStoreMock.Object, 
                optionsAccessorMock.Object, 
                passwordHasherMock.Object,
                new List<IUserValidator<CognitoUser>>() { userValidatorsMock.Object },
                new List<IPasswordValidator<CognitoUser>>() { passwordValidatorsMock.Object }, 
                keyNormalizer, 
                errorsMock.Object, 
                servicesMock.Object, 
                loggerUserManagerMock.Object);
        }

        [Fact]
        public async void Test_GivenAnUser_WhenCheckPassword_ThenResponseIsNotAltered()
        {
            var cognitoUser = new CognitoUser("userId", "clientId", cognitoPoolMock.Object, cognitoClientMock.Object);
            var authFlowResponse = new AuthFlowResponse("sessionId", null, null, null, null);
            userStoreMock.Setup(mock => mock.StartValidatePasswordAsync(It.IsAny<CognitoUser>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(authFlowResponse)).Verifiable();

            var output = await userManager.CheckPasswordAsync(cognitoUser, "password").ConfigureAwait(false);
            Assert.Equal(authFlowResponse, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAnUser_WhenRespondToTwoFactorChallenge_ThenResponseIsNotAltered()
        {
            var cognitoUser = new CognitoUser("userId", "clientId", cognitoPoolMock.Object, cognitoClientMock.Object);
            var authFlowResponse = new AuthFlowResponse("sessionId", null, null, null, null);
            userStoreMock.Setup(mock => mock.RespondToTwoFactorChallengeAsync(It.IsAny<CognitoUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(authFlowResponse)).Verifiable();

            var output = await userManager.RespondToTwoFactorChallengeAsync(cognitoUser, "2FACODE", "SessionId").ConfigureAwait(false);
            Assert.Equal(authFlowResponse, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAnUser_WhenSetTwoFactorEnabled_ThenReturnIdentityResultSuccess()
        {
            var cognitoUser = new CognitoUser("userId", "clientId", cognitoPoolMock.Object, cognitoClientMock.Object);
            var output = await userManager.SetTwoFactorEnabledAsync(cognitoUser, true).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAnUser_WhenChangePassword_ThenResponseIsNotAltered()
        {
            var cognitoUser = new CognitoUser("userId", "clientId", cognitoPoolMock.Object, cognitoClientMock.Object);
            userStoreMock.Setup(mock => mock.ChangePasswordAsync(It.IsAny<CognitoUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();

            var output = await userManager.ChangePasswordAsync(cognitoUser, "old", "new").ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAnUser_WhenIsPasswordChangeRequired_ThenResponseIsNotAltered()
        {
            var cognitoUser = new CognitoUser("userId", "clientId", cognitoPoolMock.Object, cognitoClientMock.Object, null, "FORCE_CHANGE_PASSWORD");
            var output = await userManager.IsPasswordChangeRequiredAsync(cognitoUser).ConfigureAwait(false);
            Assert.True(output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAnUserAndNewPassword_WhenResetPassword_ThenResponseIsNotAltered()
        {
            var cognitoUser = new CognitoUser("userId", "clientId", cognitoPoolMock.Object, cognitoClientMock.Object);

            userStoreMock.Setup(mock => mock.ChangePasswordWithTokenAsync(It.IsAny<CognitoUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();

            var output = await userManager.ResetPasswordAsync(cognitoUser, "token", "newPassword").ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAnUser_WhenResetPassword_ThenResponseIsNotAltered()
        {
            var cognitoUser = new CognitoUser("userId", "clientId", cognitoPoolMock.Object, cognitoClientMock.Object);

            userStoreMock.Setup(mock => mock.ResetPasswordAsync(It.IsAny<CognitoUser>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();

            var output = await userManager.ResetPasswordAsync(cognitoUser).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        #region ExceptionTests

        [Fact]
        public async void Test_GivenANullUser_WhenCheckPassword_ThenThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => userManager.CheckPasswordAsync(null, "password")).ConfigureAwait(false);
        }

        [Fact]
        public async void Test_GivenANullUser_WhenRespondToTwoFactorChallenge_ThenThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => userManager.RespondToTwoFactorChallengeAsync(null, "2FACODE", "SessionId")).ConfigureAwait(false);
        }

        [Fact]
        public async void Test_GivenANullUser_WhenSetTwoFactorEnabled_ThenThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => userManager.SetTwoFactorEnabledAsync(null, true)).ConfigureAwait(false);
        }

        [Fact]
        public async void Test_GivenANullUser_WhenChangePassword_ThenThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => userManager.ChangePasswordAsync(null, "old", "new")).ConfigureAwait(false);
        }

        [Fact]
        public async void Test_GivenANullUser_WhenResetPasswordAsync_ThenThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => userManager.ResetPasswordAsync(null)).ConfigureAwait(false);
        }


        #endregion
    }
}
