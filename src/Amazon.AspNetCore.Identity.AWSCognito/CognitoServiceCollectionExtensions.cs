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

using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System;

namespace Amazon.AspNetCore.Identity.AWSCognito
{
    public static class CognitoServiceCollectionExtensions
    {
        public static IServiceCollection AddCognitoIdentity(this IServiceCollection services, Action<IdentityOptions> identityOptions = null)
        {
            services.InjectCognitoUser<CognitoUser>(identityOptions);
            services.TryAddAWSService<IAmazonCognitoIdentityProvider>(ServiceLifetime.Singleton);
            services.TryAddSingleton<CognitoUserPool>((sp => CognitoUserPoolFactory.CreateCognitoUserPoolClient(services.BuildServiceProvider())));
            return services;
        }

        private static IServiceCollection InjectCognitoUser<TUser>(this IServiceCollection services, Action<IdentityOptions> identityOptions = null) where TUser : CognitoUser
        {
            if (identityOptions != null)
            {
                services.Configure(identityOptions);
            }

            services.AddIdentity<CognitoUser, CognitoRole>()
                .AddDefaultTokenProviders()
                .AddPasswordValidator<CognitoPasswordValidator>();

            // Overrides the managers/stores with Cognito specific ones.
            services.AddScoped<UserManager<TUser>, CognitoUserManager<TUser>>();
            services.AddScoped<SignInManager<TUser>, CognitoSignInManager<TUser>>();
            services.AddScoped<IUserStore<TUser>, CognitoUserStore<TUser>>();
            services.AddScoped<IRoleStore<CognitoRole>, CognitoRoleStore<CognitoRole>>();
            services.AddScoped<IUserClaimStore<TUser>, CognitoUserStore<TUser>>();
            services.AddScoped<IUserClaimsPrincipalFactory<TUser>, CognitoUserClaimsPrincipalFactory<TUser>>();
            services.AddScoped<CognitoKeyNormalizer, CognitoKeyNormalizer>();

            services.AddHttpContextAccessor();
            return services;
        }
    }

    public static class CognitoUserPoolFactory
    {
        private const string ConfigurationClientIdKey = "AWS:Cognito:UserPoolClientId";
        private const string ConfigurationClientSecretKey = "AWS:Cognito:UserPoolClientSecret";
        private const string ConfigurationUserPoolIdKey = "AWS:Cognito:UserPoolId";
        private const string MissingKeyExceptionMessage = "The {0} value is missing from the IConfiguration instance. Make sure it is available under {1} key.";

        public static CognitoUserPool CreateCognitoUserPoolClient(IServiceProvider provider)
        {
            var configuration = provider.GetService<IConfiguration>();

            var poolClientId = configuration.GetValue<string>(ConfigurationClientIdKey);
            if(string.IsNullOrEmpty(poolClientId))
            {
                throw new InvalidOperationException(string.Format(MissingKeyExceptionMessage, "User Pool Client Id", ConfigurationClientIdKey));
            }

            var poolClientSecret = configuration.GetValue<string>(ConfigurationClientSecretKey);
            if (string.IsNullOrEmpty(poolClientSecret))
            {
                throw new InvalidOperationException(string.Format(MissingKeyExceptionMessage, "User Pool Client Secret", ConfigurationClientSecretKey));
            }

            var poolId = configuration.GetValue<string>(ConfigurationUserPoolIdKey);
            if (string.IsNullOrEmpty(poolClientSecret))
            {
                throw new InvalidOperationException(string.Format(MissingKeyExceptionMessage, "User Pool Id", ConfigurationUserPoolIdKey));
            }

            var cognitoClient = (IAmazonCognitoIdentityProvider)provider.GetService(typeof(IAmazonCognitoIdentityProvider));
            var cognitoPool = new CognitoUserPool(poolId, poolClientId, cognitoClient, poolClientSecret);
            return cognitoPool;
        }
    }
}
