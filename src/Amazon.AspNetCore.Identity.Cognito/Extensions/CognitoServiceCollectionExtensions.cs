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

using Amazon.AspNetCore.Identity.Cognito;
using Amazon.AspNetCore.Identity.Cognito.Exceptions;
using Amazon.AspNetCore.Identity.Cognito.Extensions;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using System;
using System.Linq;
using System.Reflection;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class CognitoServiceCollectionExtensions
    {
        public static IServiceCollection AddCognitoIdentity(this IServiceCollection services, Action<IdentityOptions> identityOptions = null, string prefix = null)
        {
            services.InjectCognitoUser<CognitoUser>(identityOptions);
            services.TryAddAWSService<IAmazonCognitoIdentityProvider>();
            services.TryAddCognitoUserPool();
            return services;
        }

        private static IServiceCollection InjectCognitoUser<TUser>(this IServiceCollection services, Action<IdentityOptions> identityOptions = null) where TUser : CognitoUser
        {
            if (identityOptions != null)
            {
                services.Configure(identityOptions);
                services.AddIdentity<CognitoUser, CognitoRole>()
                    .AddDefaultTokenProviders()
                    .AddPasswordValidator<CognitoPasswordValidator>();
            }
            else
            {
                services.AddIdentity<CognitoUser, CognitoRole>()
                    .AddDefaultTokenProviders()
                    .AddPasswordValidator<CognitoPasswordValidator>();
                var passwordValidators = services.Where(s => s.ServiceType.Equals(typeof(IPasswordValidator<CognitoUser>)));
                foreach (var validator in passwordValidators.ToArray())
                {
                    if (Equals(validator.ImplementationType, typeof(PasswordValidator<CognitoUser>)))
                    {
                        services.Remove(validator);
                    }
                }
            }

            // Overrides the managers/stores with Cognito specific ones.
            services.AddScoped<UserManager<TUser>, CognitoUserManager<TUser>>();
            services.AddScoped<SignInManager<TUser>, CognitoSignInManager<TUser>>();
            services.AddScoped<IUserStore<TUser>, CognitoUserStore<TUser>>();
            services.AddScoped<IRoleStore<CognitoRole>, CognitoRoleStore<CognitoRole>>();
            services.AddScoped<IUserClaimStore<TUser>, CognitoUserStore<TUser>>();
            services.AddScoped<IUserClaimsPrincipalFactory<TUser>, CognitoUserClaimsPrincipalFactory<TUser>>();
            services.AddSingleton<CognitoKeyNormalizer, CognitoKeyNormalizer>();
            services.AddSingleton<IdentityErrorDescriber, CognitoIdentityErrorDescriber>();

            services.AddHttpContextAccessor();
            return services;
        }

        private static IServiceCollection TryAddCognitoUserPool(this IServiceCollection services, ServiceLifetime lifetime = ServiceLifetime.Singleton)
        {
            if (!services.Any(x => x.ServiceType == typeof(CognitoUserPool)))
            {
                Func<IServiceProvider, CognitoUserPool> factory =
                    CognitoUserPoolFactory.CreateUserPoolClient;

                var descriptor = new ServiceDescriptor(typeof(CognitoUserPool), factory, lifetime);
                services.Add(descriptor);
            }
            return services;
        }
    }

    internal static class CognitoUserPoolFactory
    {
        private const string MissingConfigurationExceptionMessage = "No IConfiguration object instance was found in the service collection. Could not instanciate a CognitoUserPool object.";
        private const string UserAgentHeader = "User-Agent";
        private static readonly string _assemblyFileVersion = GetAssemblyFileVersion();
        private static readonly string _userAgentSuffix = $"lib/CognitoASPNETCoreIdentityProvider#{_assemblyFileVersion}";

        public static CognitoUserPool CreateUserPoolClient(IServiceProvider provider)
        {
            // Checks if AWSCognitoClientOptions are already set up
            var options = provider.GetService<AWSCognitoClientOptions>();
            if (options == null)
            {
                var configuration = provider.GetService<IConfiguration>();
                if (configuration != null)
                {
                    options = configuration.GetAWSCognitoClientOptions();
                }
                else
                {
                    throw new CognitoConfigurationException(MissingConfigurationExceptionMessage);
                }
            }

            var cognitoClient = provider.GetService<IAmazonCognitoIdentityProvider>();

            if (cognitoClient is AmazonCognitoIdentityProviderClient eventProvider)
            {
                eventProvider.BeforeRequestEvent += ServiceClientBeforeRequestEvent;
            }

            var cognitoPool = new CognitoUserPool(options.UserPoolId, options.UserPoolClientId, cognitoClient, options.UserPoolClientSecret);
            return cognitoPool;
        }

        private static void ServiceClientBeforeRequestEvent(object sender, Amazon.Runtime.RequestEventArgs e)
        {
            Amazon.Runtime.WebServiceRequestEventArgs args = e as Amazon.Runtime.WebServiceRequestEventArgs;
            if (args == null || !args.Headers.ContainsKey(UserAgentHeader) || args.Headers[UserAgentHeader].Contains(_userAgentSuffix))
                return;

            args.Headers[UserAgentHeader] = args.Headers[UserAgentHeader] + " " + _userAgentSuffix;
        }

        private static string GetAssemblyFileVersion()
        {
            var assembly = typeof(CognitoServiceCollectionExtensions).GetTypeInfo().Assembly;
            AssemblyFileVersionAttribute attribute = assembly.GetCustomAttribute(typeof(AssemblyFileVersionAttribute)) as AssemblyFileVersionAttribute;
            return attribute == null ? "Unknown" : attribute.Version;
        }
    }
}