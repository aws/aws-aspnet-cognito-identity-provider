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

using Amazon.CognitoIdentityProvider.Model;
using Moq;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Amazon.AspNetCore.Identity.Cognito.Test
{
    public partial class CognitoUserStoreTest
    {
        private AdminGetUserResponse GET_USER_RESPONSE = new AdminGetUserResponse
        {
            UserAttributes = new List<AttributeType>()
                {
                    new AttributeType()
                    {
                        Name = "Name1",
                        Value = "Value1"
                    },
                    new AttributeType()
                    {
                        Name = "Name2",
                        Value = "Value2"
                    },
                    new AttributeType()
                    {
                        Name = "Name2",
                        Value = "Value2"
                    }
                }
        };

        [Fact]
        public async void Test_GivenAUser_WhenGetClaims_ThenTheListOfClaimsIsRetrieved()
        {
            _cognitoClientMock.Setup(mock => mock.AdminGetUserAsync(It.IsAny<AdminGetUserRequest>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(GET_USER_RESPONSE)).Verifiable();
            var output = await _store.GetClaimsAsync(_userMock.Object, CancellationToken.None).ConfigureAwait(false);
            Assert.Equal(GET_USER_RESPONSE.UserAttributes.Count, output.Count);
            Assert.Equal(GET_USER_RESPONSE.UserAttributes[2].Name, output[2].Type);
            Assert.Equal(GET_USER_RESPONSE.UserAttributes[1].Value, output[1].Value);
            _cognitoClientMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenAddClaimsWithPopulatedListOfClaims_ThenAdminUpdateUserAttributesIsCalled()
        {
            var claims = new List<Claim>()
            {
                new Claim("Name1", "Value1")
            };
            _cognitoClientMock.Setup(mock => mock.AdminUpdateUserAttributesAsync(It.IsAny<AdminUpdateUserAttributesRequest>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(new AdminUpdateUserAttributesResponse())).Verifiable();
            await _store.AddClaimsAsync(_userMock.Object, claims, CancellationToken.None).ConfigureAwait(false);
            _cognitoClientMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenAddClaimsWithEmptyListOfClaims_ThenAdminUpdateUserAttributesIsNeverCalled()
        {
            var claims = new List<Claim>();
            await _store.AddClaimsAsync(_userMock.Object, claims, CancellationToken.None).ConfigureAwait(false);
            _cognitoClientMock.Verify(mock => mock.AdminUpdateUserAttributesAsync(It.IsAny<AdminUpdateUserAttributesRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async void Test_GivenAUser_WhenRemoveClaimsWithAValidClaim_ThenAdminDeleteUserAttributesIsCalled()
        {
            var claims = new List<Claim>()
            {
                new Claim("Name1", "Value1")
            };
            _cognitoClientMock.Setup(mock => mock.AdminGetUserAsync(It.IsAny<AdminGetUserRequest>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(GET_USER_RESPONSE)).Verifiable();
            _cognitoClientMock.Setup(mock => mock.AdminDeleteUserAttributesAsync(It.IsAny<AdminDeleteUserAttributesRequest>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(new AdminDeleteUserAttributesResponse())).Verifiable();
            await _store.RemoveClaimsAsync(_userMock.Object, claims, CancellationToken.None).ConfigureAwait(false);
            _cognitoClientMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenRemoveClaimsWithAnInvalidClaim_ThenAdminDeleteUserAttributesIsNeverCalled()
        {
            var claims = new List<Claim>()
            {
                new Claim("Unknown", "Unknown")
            };
            _cognitoClientMock.Setup(mock => mock.AdminGetUserAsync(It.IsAny<AdminGetUserRequest>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(GET_USER_RESPONSE)).Verifiable();
            _cognitoClientMock.Setup(mock => mock.AdminDeleteUserAttributesAsync(It.IsAny<AdminDeleteUserAttributesRequest>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(new AdminDeleteUserAttributesResponse())).Verifiable();
            await _store.RemoveClaimsAsync(_userMock.Object, claims, CancellationToken.None).ConfigureAwait(false);
            _cognitoClientMock.Verify(mock => mock.AdminDeleteUserAttributesAsync(It.IsAny<AdminDeleteUserAttributesRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async void Test_GivenAUser_WhenReplaceClaim_ThenThrowsANotSupportedException()
        {
            await Assert.ThrowsAsync<NotSupportedException>(() => _store.ReplaceClaimAsync(null, null, null, CancellationToken.None)).ConfigureAwait(false);
        }

        [Fact]
        public async void Test_GivenAClaim_WhenGetUsersForClaim_ThenThrowsANotSupportedException()
        {
            await Assert.ThrowsAsync<NotSupportedException>(() => _store.GetUsersForClaimAsync(new Claim("test", "test"), CancellationToken.None)).ConfigureAwait(false);
        }

    }
}
