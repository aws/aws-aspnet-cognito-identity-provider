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
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.AWSCognito
{
    public class CognitoRoleStore<TRole> : IRoleStore<TRole> where TRole : CognitoRole
    {

        private AmazonCognitoIdentityProviderClient _provider;
        private CognitoUserPool _pool;

        public CognitoRoleStore(AmazonCognitoIdentityProviderClient provider, CognitoUserPool pool)
        {
            _provider = provider ?? throw new ArgumentNullException(nameof(provider));
            _pool = pool ?? throw new ArgumentNullException(nameof(pool));
        }

        /// <summary>
        /// Creates a new role in the store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role to create in the store.</param>
        /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
        public async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            await _provider.CreateGroupAsync(new CreateGroupRequest()
            {
                Description = role.Description,
                GroupName = role.Name,
                Precedence = role.Precedence,
                RoleArn = role.RoleArn,
                UserPoolId = _pool.PoolID

            }, cancellationToken).ConfigureAwait(false);

            return IdentityResult.Success;
        }

        /// <summary>
        /// Deletes a role from the store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role to delete from the store.</param>
        /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
        public async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            await _provider.DeleteGroupAsync(new DeleteGroupRequest()
            {
                GroupName = role.Name,
                UserPoolId = _pool.PoolID

            }, cancellationToken).ConfigureAwait(false);

            return IdentityResult.Success;
        }

        /// <summary>
        /// Finds the role who has the specified normalized name as an asynchronous operation.
        /// </summary>
        /// <param name="roleName">The role name to look for.</param>
        /// <returns>A <see cref="Task{TResult}"/> that represents the result of the look up.</returns>
        public async Task<TRole> FindByNameAsync(string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var response = await _provider.GetGroupAsync(new GetGroupRequest()
            {
                GroupName = roleName,
                UserPoolId = _pool.PoolID

            }, cancellationToken).ConfigureAwait(false);

            return new CognitoRole(response.Group.GroupName, response.Group.Description,
                response.Group.Precedence, response.Group.RoleArn) as TRole;
        }

        /// <summary>
        /// Updates a role in a store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role to update in the store.</param>
        /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
        public async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            await _provider.UpdateGroupAsync(new UpdateGroupRequest()
            {
                Description = role.Description,
                GroupName = role.Name,
                Precedence = role.Precedence,
                RoleArn = role.RoleArn,
                UserPoolId = _pool.PoolID

            }, cancellationToken).ConfigureAwait(false);

            return IdentityResult.Success;
        }

        /// <summary>
        /// Gets the name of a role as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose name should be returned.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the name of the role.</returns>
        public Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            return Task.FromResult(role.Name);
        }

        public Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken)
        {
            throw new NotSupportedException("Changing role names in not supported.");
        }

        public Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken)
        {
            throw new NotSupportedException("Cognito does not expose group ids, use GetRoleNameAsync() instead");
        }

        public Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            throw new NotSupportedException("Cognito does not expose group ids, use FindByNameAsync() instead");
        }

        public Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken)
        {
            throw new NotSupportedException("Cognito is case-sensitive and does not support normalized group names. Use SetRoleNameAsync() instead");
        }
        public Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            throw new NotSupportedException("Cognito is case-sensitive and does not support normalized group names. Use GetRoleNameAsync() instead");
        }

        #region IDisposable
        private bool disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (disposed)
                return;

            if (disposing)
            {

            }

            disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion

    }
}
