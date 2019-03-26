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
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Amazon.AspNetCore.Identity.Cognito.Tests
{
    public partial class CognitoUserStoreTests
    {
        [Fact]
        public async void Test_GivenAnEmail_WhenFindByEmail_ThenTheUserIsRetrieved()
        {
            var username = "UserName";
            var status = "CONFIRMED";
            var response = new ListUsersResponse()
            {
                Users = new List<UserType>()
                {
                    new UserType()
                    {
                        Username = username,
                        UserStatus = status,
                        Attributes = new List<AttributeType>()
                    }
                }
            };
            _cognitoClientMock.Setup(mock => mock.ListUsersAsync(It.IsAny<ListUsersRequest>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(response)).Verifiable();
            var user = await _store.FindByEmailAsync("user@domain.tld", CancellationToken.None).ConfigureAwait(false);
            Assert.Equal(username, user.Username);
            Assert.Equal(status, user.Status);
            _cognitoClientMock.Verify();
        }

        [Fact]
        public async void Test_GivenAUser_WhenGetNormalizedEmail_ThenThrowsANotSupportedException()
        {
            await Assert.ThrowsAsync<NotSupportedException>(() => _store.GetNormalizedEmailAsync(_userMock.Object, CancellationToken.None)).ConfigureAwait(false);
        }

        [Fact]
        public async void Test_GivenAUser_WhenSetEmailConfirmed_ThenThrowsANotSupportedException()
        {
            await Assert.ThrowsAsync<NotSupportedException>(() => _store.SetEmailConfirmedAsync(_userMock.Object, true, CancellationToken.None)).ConfigureAwait(false);
        }

        [Fact]
        public async void Test_GivenAUser_WhenSetNormalizedEmail_ThenThrowsANotSupportedException()
        {
            await Assert.ThrowsAsync<NotSupportedException>(() => _store.SetNormalizedEmailAsync(_userMock.Object, "email", CancellationToken.None)).ConfigureAwait(false);
        }
    }
}
