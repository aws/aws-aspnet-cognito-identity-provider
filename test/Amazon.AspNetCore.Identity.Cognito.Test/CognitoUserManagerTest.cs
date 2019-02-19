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
using System.Security.Claims;
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
        public async void Test_GivenAUser_WhenCheckPassword_ThenResponseIsNotAltered()
        {
            var authFlowResponse = new AuthFlowResponse("sessionId", null, null, null, null);
            userStoreMock.Setup(mock => mock.StartValidatePasswordAsync(It.IsAny<CognitoUser>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(authFlowResponse)).Verifiable();
            var output = await userManager.CheckPasswordAsync(GetCognitoUser(), "password").ConfigureAwait(false);
            Assert.Equal(authFlowResponse, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenRespondToTwoFactorChallenge_ThenResponseIsNotAltered()
        {
            var authFlowResponse = new AuthFlowResponse("sessionId", null, null, null, null);
            userStoreMock.Setup(mock => mock.RespondToTwoFactorChallengeAsync(It.IsAny<CognitoUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(authFlowResponse)).Verifiable();
            var output = await userManager.RespondToTwoFactorChallengeAsync(GetCognitoUser(), "2FACODE", "SessionId").ConfigureAwait(false);
            Assert.Equal(authFlowResponse, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenSetTwoFactorEnabled_ThenReturnIdentityResultSuccess()
        {
            var output = await userManager.SetTwoFactorEnabledAsync(GetCognitoUser(), true).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenChangePassword_ThenResponseIsNotAltered()
        {
            userStoreMock.Setup(mock => mock.ChangePasswordAsync(It.IsAny<CognitoUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();
            var output = await userManager.ChangePasswordAsync(GetCognitoUser(), "old", "new").ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenIsPasswordChangeRequired_ThenResponseIsNotAltered()
        {
            userStoreMock.Setup(mock => mock.IsPasswordChangeRequiredAsync(It.IsAny<CognitoUser>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(true)).Verifiable();
            var output = await userManager.IsPasswordChangeRequiredAsync(GetCognitoUser()).ConfigureAwait(false);
            Assert.True(output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUserAndNewPassword_WhenResetPassword_ThenResponseIsNotAltered()
        {
            userStoreMock.Setup(mock => mock.ChangePasswordWithTokenAsync(It.IsAny<CognitoUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();
            var output = await userManager.ResetPasswordAsync(GetCognitoUser(), "token", "newPassword").ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenSendEmailOrPhoneConfirmationToken_ThenResponseIsNotAltered()
        {
            var cognitoUser = GetCognitoUser();
            userStoreMock.Setup(mock => mock.GetUserAttributeVerificationCodeAsync(It.IsAny<CognitoUser>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();
            var output = await userManager.SendEmailConfirmationTokenAsync(cognitoUser).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            output = await userManager.SendPhoneConfirmationTokenAsync(cognitoUser).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenCreate_ThenResponseIsNotAltered()
        {
            var cognitoUser = GetCognitoUser();
            userStoreMock.Setup(mock => mock.CreateAsync(It.IsAny<CognitoUser>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();
            userStoreMock.Setup(mock => mock.CreateAsync(It.IsAny<CognitoUser>(), It.IsAny<string>(), It.IsAny<IDictionary<string, string>>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();
            passwordValidatorsMock.Setup(mock => mock.ValidateAsync(It.IsAny<CognitoUserManager<CognitoUser>>(), It.IsAny<CognitoUser>(), It.IsAny<string>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();
            var output = await userManager.CreateAsync(cognitoUser).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            output = await userManager.CreateAsync(cognitoUser, "password").ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenResetPassword_ThenResponseIsNotAltered()
        {
            userStoreMock.Setup(mock => mock.ResetPasswordAsync(It.IsAny<CognitoUser>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();
            var output = await userManager.ResetPasswordAsync(GetCognitoUser()).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenConfirmEmailOrPhoneNumber_ThenResponseIsNotAltered()
        {
            var cognitoUser = GetCognitoUser();
            userStoreMock.Setup(mock => mock.VerifyUserAttributeAsync(It.IsAny<CognitoUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();
            var output = await userManager.ConfirmEmailAsync(cognitoUser, "code").ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            output = await userManager.ConfirmPhoneNumberAsync(cognitoUser, "code").ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenConfirmSignUp_ThenResponseIsNotAltered()
        {
            userStoreMock.Setup(mock => mock.ConfirmSignUpAsync(It.IsAny<CognitoUser>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();
            var output = await userManager.ConfirmSignUpAsync(GetCognitoUser(), "code", true).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenAdminConfirmSignUp_ThenResponseIsNotAltered()
        {
            userStoreMock.Setup(mock => mock.AdminConfirmSignUpAsync(It.IsAny<CognitoUser>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();
            var output = await userManager.AdminConfirmSignUpAsync(GetCognitoUser()).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenResendSignupConfirmationCode_ThenResponseIsNotAltered()
        {
            userStoreMock.Setup(mock => mock.ResendSignupConfirmationCodeAsync(It.IsAny<CognitoUser>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();
            var output = await userManager.ResendSignupConfirmationCodeAsync(GetCognitoUser()).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenSetPhoneNumber_ThenResponseIsNotAltered()
        {
            userStoreMock.Setup(mock => mock.SetPhoneNumberAsync(It.IsAny<CognitoUser>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(0)).Verifiable();
            userStoreMock.Setup(mock => mock.UpdateAsync(It.IsAny<CognitoUser>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();
            var output = await userManager.SetPhoneNumberAsync(GetCognitoUser(), "+1234567890").ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenSetEmail_ThenResponseIsNotAltered()
        {
            userStoreMock.Setup(mock => mock.SetEmailAsync(It.IsAny<CognitoUser>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(0)).Verifiable();
            userStoreMock.Setup(mock => mock.UpdateAsync(It.IsAny<CognitoUser>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();
            var output = await userManager.SetEmailAsync(GetCognitoUser(), "darth.vader@amazon.com").ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivennUser_WhenUpdateUser_ThenResponseIsNotAltered()
        {
            userStoreMock.Setup(mock => mock.UpdateAsync(It.IsAny<CognitoUser>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();
            var output = await userManager.UpdateAsync(GetCognitoUser()).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenAddClaims_ThenResponseIsNotAltered()
        {
            userStoreMock.Setup(mock => mock.AddClaimsAsync(It.IsAny<CognitoUser>(), It.IsAny<IEnumerable<Claim>>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();
            var output = await userManager.AddClaimsAsync(GetCognitoUser(), new List<Claim>()).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenRemoveClaims_ThenResponseIsNotAltered()
        {
            userStoreMock.Setup(mock => mock.RemoveClaimsAsync(It.IsAny<CognitoUser>(), It.IsAny<IEnumerable<Claim>>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(IdentityResult.Success)).Verifiable();
            var output = await userManager.RemoveClaimsAsync(GetCognitoUser(), new List<Claim>()).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            userStoreMock.Verify();
        }

        [Fact]
        public async void Test_GivenAListOfUsers_WhenGetUsers_ThenResponseIsNotAltered()
        {
            var user1 = new CognitoUser("userId1", "clientId", cognitoPoolMock.Object, cognitoClientMock.Object);
            var user2 = new CognitoUser("userId2", "clientId", cognitoPoolMock.Object, cognitoClientMock.Object);
            var user3 = new CognitoUser("userId3", "clientId", cognitoPoolMock.Object, cognitoClientMock.Object);
            IEnumerable<CognitoUser> users = new List<CognitoUser>()
            {
                user1,
                user2,
                user3
            };
            userStoreMock.Setup(mock => mock.GetUsersAsync("", "", "", It.IsAny<CancellationToken>())).Returns(Task.FromResult(users)).Verifiable();
            var output = await userManager.GetUsersAsync().ConfigureAwait(false);
            Assert.Equal(users, output);
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
        public async void Test_GivenANullUser_WhenResetPassword_ThenThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => userManager.ResetPasswordAsync(null)).ConfigureAwait(false);
        }

        [Fact]
        public async void Test_GivenANullUser_WhenUpdate_ThenThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => userManager.UpdateAsync(null)).ConfigureAwait(false);
        }

        [Fact]
        public async void Test_GivenANullUser_WhenAddClaims_ThenThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => userManager.AddClaimsAsync(null, new List<Claim>())).ConfigureAwait(false);
        }

        [Fact]
        public async void Test_GivenAUserAndNullListOfClaim_WhenAddClaims_ThenThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => userManager.AddClaimsAsync(GetCognitoUser(), null)).ConfigureAwait(false);
        }

        [Fact]
        public async void Test_GivenANullUser_WhenRemoveClaims_ThenThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => userManager.RemoveClaimsAsync(null, new List<Claim>())).ConfigureAwait(false);
        }

        [Fact]
        public async void Test_GivenAUserAndNullListOfClaim_WhenRemoveClaims_ThenThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => userManager.RemoveClaimsAsync(GetCognitoUser(), null)).ConfigureAwait(false);
        }

        [Fact]
        public async void Test_GivenAUser_WhenGenerateEmailConfirmationToken_ThenThrowsANotSupportedException()
        {
            await Assert.ThrowsAsync<NotSupportedException>(() => userManager.GenerateEmailConfirmationTokenAsync(null)).ConfigureAwait(false);
        }

        [Fact]
        public async void Test_GivenAUser_WhenGenerateChangePhoneNumberToken_ThenThrowsANotSupportedException()
        {
            await Assert.ThrowsAsync<NotSupportedException>(() => userManager.GenerateChangePhoneNumberTokenAsync(null, null)).ConfigureAwait(false);
        }

        [Fact]
        public async void Test_GivenAUser_WhenChangeEmail_ThenThrowsANotSupportedException()
        {
            await Assert.ThrowsAsync<NotSupportedException>(() => userManager.ChangeEmailAsync(null, null, null)).ConfigureAwait(false);
        }

        [Fact]
        public void Test_GivenAListOfUsers_WhenCallingUsersProperty_ThenThrowsANotSupportedException()
        {
            Assert.Throws<NotSupportedException>(() => userManager.Users);
        }

        #endregion
    }
}
