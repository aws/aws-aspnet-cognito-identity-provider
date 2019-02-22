/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Moq;
using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Amazon.AspNetCore.Identity.Cognito.Test
{
    public partial class CognitoUserStoreTest
    {
        private Mock<IAmazonCognitoIdentityProvider> _cognitoClientMock;
        private Mock<CognitoUserPool> _cognitoPoolMock;
        private Mock<CognitoIdentityErrorDescriber> _errorsMock;
        private Mock<CognitoUser> _userMock;
        private CognitoUserStore<CognitoUser> _store;

        public CognitoUserStoreTest()
        {
            _cognitoClientMock = new Mock<IAmazonCognitoIdentityProvider>();
            _cognitoPoolMock = new Mock<CognitoUserPool>("region_poolName", "clientID", _cognitoClientMock.Object, null);
            _errorsMock = new Mock<CognitoIdentityErrorDescriber>();
            _userMock = new Mock<CognitoUser>("userID", "clientID", _cognitoPoolMock.Object, _cognitoClientMock.Object, null, null, null, null);
            _store = new CognitoUserStore<CognitoUser>(_cognitoClientMock.Object, _cognitoPoolMock.Object, _errorsMock.Object);
        }

        [Theory]
        [InlineData("FORCE_CHANGE_PASSWORD", true)]
        [InlineData("CONFIRMED", false)]
        public async void Test_GivenAUserWithStatus_WhenIsPasswordChangeRequired_ThenResponseIsValid(string status, bool isPasswordChangeRequired)
        {
            var user = new CognitoUser("userID", "clientID", _cognitoPoolMock.Object, _cognitoClientMock.Object, null, status, null, null);
            var output = await _store.IsPasswordChangeRequiredAsync(user, CancellationToken.None).ConfigureAwait(false);
            Assert.Equal(isPasswordChangeRequired, output);
        }

        [Theory]
        [InlineData("RESET_REQUIRED", true)]
        [InlineData("CONFIRMED", false)]
        public async void Test_GivenAUserWithStatus_WhenIsPasswordResetRequired_ThenResponseIsValid(string status, bool isPasswordResetRequired)
        {
            var user = new CognitoUser("userID", "clientID", _cognitoPoolMock.Object, _cognitoClientMock.Object, null, status, null, null);
            var output = await _store.IsPasswordResetRequiredAsync(user, CancellationToken.None).ConfigureAwait(false);
            Assert.Equal(isPasswordResetRequired, output);
        }

        [Fact]
        public async void Test_GivenAUser_WhenResetPassword_ThenTheRequestIsSuccessful()
        {
            _cognitoClientMock.Setup(mock => mock.AdminResetUserPasswordAsync(It.IsAny<AdminResetUserPasswordRequest>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(new AdminResetUserPasswordResponse())).Verifiable();
            var output = await _store.ResetPasswordAsync(_userMock.Object, CancellationToken.None).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            _cognitoClientMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenCreate_ThenTheUserGetsAddedToThePool()
        {
            var output = await _store.CreateAsync(_userMock.Object, "password", null, CancellationToken.None).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
        }

        [Fact]
        public async void Test_GivenAUser_WhenAdminConfirmSignUp_ThenTheRequestIsSuccessful()
        {
            _cognitoClientMock.Setup(mock => mock.AdminConfirmSignUpAsync(It.IsAny<AdminConfirmSignUpRequest>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(new AdminConfirmSignUpResponse())).Verifiable();
            var output = await _store.AdminConfirmSignUpAsync(_userMock.Object, CancellationToken.None).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            _cognitoClientMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenGetUserAttributeVerificationCodeOtherThanEmailOrPhone_ThenThrowsArgumentException()
        {
            await Assert.ThrowsAsync<ArgumentException>(() => _store.GetUserAttributeVerificationCodeAsync(_userMock.Object, "UNKNOWN_ATTRIBUTE", CancellationToken.None)).ConfigureAwait(false);
        }

        [Fact]
        public async void Test_GivenAUser_WhenGetUserAttributeVerificationCode_ThenTheRequestIsSuccessfun()
        {
            _cognitoClientMock.Setup(mock => mock.GetUserAttributeVerificationCodeAsync(It.IsAny<GetUserAttributeVerificationCodeRequest>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(new GetUserAttributeVerificationCodeResponse())).Verifiable();
            _userMock.Object.SessionTokens = new CognitoUserSession(null, null, null, DateTime.Now, DateTime.MaxValue);
            var output = await _store.GetUserAttributeVerificationCodeAsync(_userMock.Object, CognitoAttribute.PhoneNumber.AttributeName, CancellationToken.None).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            _cognitoClientMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenVerifyUserAttribute_ThenTheRequestIsSuccessfun()
        {
            _cognitoClientMock.Setup(mock => mock.VerifyUserAttributeAsync(It.IsAny<VerifyUserAttributeRequest>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(new VerifyUserAttributeResponse())).Verifiable();
            _userMock.Object.SessionTokens = new CognitoUserSession(null, null, null, DateTime.Now, DateTime.MaxValue);
            var output = await _store.VerifyUserAttributeAsync(_userMock.Object, CognitoAttribute.PhoneNumber.AttributeName, "code", CancellationToken.None).ConfigureAwait(false);
            Assert.Equal(IdentityResult.Success, output);
            _cognitoClientMock.Verify();
        }
    }
}
