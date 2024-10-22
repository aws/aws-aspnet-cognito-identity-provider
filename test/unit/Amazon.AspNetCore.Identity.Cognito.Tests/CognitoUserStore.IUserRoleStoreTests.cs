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
        AdminListGroupsForUserResponse LIST_GROUPS_FOR_USERS_RESPONSE = new AdminListGroupsForUserResponse()
        {
            Groups = new List<GroupType>()
                {
                    new GroupType() { GroupName = "group1"},
                    new GroupType() { GroupName = "group2"},
                    new GroupType() { GroupName = "group3"},
                }
        };

        [Fact]
        public async Task Test_GivenAUser_WhenGetUserId_ThenTheUserIdIsRetrieved()
        {
            var userId = await _store.GetUserIdAsync(_userMock.Object, CancellationToken.None);
            Assert.Equal(_userMock.Object.UserID, userId);
        }

        [Fact]
        public async Task Test_GivenAUser_WhenGetUserName_ThenTheUserNameIsRetrieved()
        {
            var userName = await _store.GetUserNameAsync(_userMock.Object, CancellationToken.None);
            Assert.Equal(_userMock.Object.Username, userName);
        }

        [Fact]
        public async Task Test_GivenAUser_WhenDelete_ThenAdminDeleteUserAsyncIsCalled()
        {
            _cognitoClientMock.Setup(mock => mock.AdminDeleteUserAsync(It.IsAny<AdminDeleteUserRequest>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(new AdminDeleteUserResponse())).Verifiable();
            await _store.DeleteAsync(_userMock.Object, CancellationToken.None);
            _cognitoClientMock.Verify();
        }

        [Fact]
        public async Task Test_GivenAUser_WhenAddToRole_ThenAdminAddUserToGroupAsyncIsCalled()
        {
            _cognitoClientMock.Setup(mock => mock.AdminAddUserToGroupAsync(It.IsAny<AdminAddUserToGroupRequest>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(new AdminAddUserToGroupResponse())).Verifiable();
            await _store.AddToRoleAsync(_userMock.Object, "roleName", CancellationToken.None);
            _cognitoClientMock.Verify();
        }

        [Fact]
        public async Task Test_GivenAUser_WhenRemoveFromRole_ThenAdminRemoveUserFromGroupAsyncIsCalled()
        {
            _cognitoClientMock.Setup(mock => mock.AdminRemoveUserFromGroupAsync(It.IsAny<AdminRemoveUserFromGroupRequest>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(new AdminRemoveUserFromGroupResponse())).Verifiable();
            await _store.RemoveFromRoleAsync(_userMock.Object, "roleName", CancellationToken.None);
            _cognitoClientMock.Verify();
        }

        [Fact]
        public async Task Test_GivenAUser_WhenGetRoles_ThenTheUserRolesAreRetrieved()
        {
            _cognitoClientMock.Setup(mock => mock.AdminListGroupsForUserAsync(It.IsAny<AdminListGroupsForUserRequest>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(LIST_GROUPS_FOR_USERS_RESPONSE)).Verifiable();
            var output = await _store.GetRolesAsync(_userMock.Object, CancellationToken.None);
            Assert.Equal(LIST_GROUPS_FOR_USERS_RESPONSE.Groups.Count, output.Count);
            Assert.Equal(LIST_GROUPS_FOR_USERS_RESPONSE.Groups[0].GroupName, output[0]);
            Assert.Equal(LIST_GROUPS_FOR_USERS_RESPONSE.Groups[1].GroupName, output[1]);
            Assert.Equal(LIST_GROUPS_FOR_USERS_RESPONSE.Groups[2].GroupName, output[2]);
            _cognitoClientMock.Verify();
        }

        [Theory]
        [InlineData("group1", true)]
        [InlineData("unknownGroup", false)]
        public async Task Test_GivenAUserAndARoleName_WhenIsInRole_ThenTheResponseIsValid(string roleName, bool isInRole)
        {
            _cognitoClientMock.Setup(mock => mock.AdminListGroupsForUserAsync(It.IsAny<AdminListGroupsForUserRequest>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(LIST_GROUPS_FOR_USERS_RESPONSE)).Verifiable();
            var output = await _store.IsInRoleAsync(_userMock.Object, roleName, CancellationToken.None);
            Assert.Equal(isInRole, output);
            _cognitoClientMock.Verify();
        }

        [Fact]
        public async Task Test_GivenAUser_WhenGetNormalizedUserName_ThenThrowsANotSupportedException()
        {
            await Assert.ThrowsAsync<NotSupportedException>(() => _store.GetNormalizedUserNameAsync(_userMock.Object, CancellationToken.None));
        }

        [Fact]
        public async Task Test_GivenAUser_WhenSetNormalizedUserName_ThenThrowsANotSupportedException()
        {
            await Assert.ThrowsAsync<NotSupportedException>(() => _store.SetNormalizedUserNameAsync(_userMock.Object, "userName", CancellationToken.None));
        }

        [Fact]
        public async Task Test_GivenAUser_WhenSetSetUserName_ThenThrowsANotSupportedException()
        {
            await Assert.ThrowsAsync<NotSupportedException>(() => _store.SetUserNameAsync(_userMock.Object, "userName", CancellationToken.None));
        }
    }
}
