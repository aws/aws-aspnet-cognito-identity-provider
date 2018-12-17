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
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.Cognito.Test
{
    public static class MockUtils
    {
        public const string loginProvider = "login";
        public const string providerKey = "fookey";

        /// <summary>
        /// This creates an http context.
        /// </summary>
        /// <param name="cognitoUser">The Cognito User to link to the context</param>
        /// <param name="scheme">The scheme to signin the user into</param>
        /// <returns></returns>
        public static DefaultHttpContext MockContext(CognitoUser cognitoUser, string scheme)
        {
            var context = new DefaultHttpContext();
            var authMock = new Mock<IAuthenticationService>();
            var userPrincipal = new ClaimsPrincipal();
            userPrincipal.AddIdentity(new ClaimsIdentity(new List<Claim>() {
                    new Claim(ClaimTypes.Name, cognitoUser.UserID),
                    new Claim(providerKey, loginProvider),
                    new Claim(ClaimTypes.AuthenticationMethod, providerKey)
                }));
            var authenticationTicket = new AuthenticationTicket(userPrincipal, scheme);
            var authenticateResult = AuthenticateResult.Success(authenticationTicket);

            context.RequestServices = new ServiceCollection().AddSingleton(authMock.Object).BuildServiceProvider();
            authMock.Setup(a => a.AuthenticateAsync(context,
               scheme)).Returns(Task.FromResult(authenticateResult)).Verifiable();

            return context;
        }

    }
}
