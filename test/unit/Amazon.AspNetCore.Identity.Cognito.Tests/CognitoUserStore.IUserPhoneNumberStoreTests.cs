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

using System;
using System.Threading;
using Xunit;

namespace Amazon.AspNetCore.Identity.Cognito.Tests
{
    public partial class CognitoUserStoreTests
    {
        [Fact]
        public async void Test_GivenAUser_WhenSetPhoneNumberConfirmed_ThenThrowsANotSupportedException()
        {
            await Assert.ThrowsAsync<NotSupportedException>(() => _store.SetPhoneNumberConfirmedAsync(_userMock.Object, true, CancellationToken.None)).ConfigureAwait(false);
        }
        
    }
}
