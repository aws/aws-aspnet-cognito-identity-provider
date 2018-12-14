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

using Amazon.AspNetCore.Identity.Cognito.Exceptions;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.Cognito
{
    public partial class CognitoUserStore<TUser> : IUserRoleStore<TUser> where TUser : CognitoUser
    {
        #region IUserStore

        /// <summary>
        /// Finds and returns a user, if any, who has the specified <paramref name="userId"/>.
        /// </summary>
        /// <param name="userId">The user ID to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userId"/> if it exists.
        /// </returns>
        public virtual async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                // The userId can be the userName, the email or the phone number depending on the User Pool login policy
                var user = await _pool.FindByIdAsync(userId).ConfigureAwait(false);
                return user as TUser;
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                throw new CognitoServiceException("Failed to find the Cognito User by Id", e);
            }
        }

        /// <summary>
        /// Returns the userId associated with the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to retrieve the id for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the userId belonging to the matching the specified <paramref name="userId"/>.
        /// </returns>
        public virtual Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(user.UserID);
        }

        /// <summary>
        /// Returns the UserName associated with the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to retrieve the UserName for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the UserName belonging to the matching the specified <paramref name="userId"/>.
        /// </returns>
        public virtual Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(user.Username);
        }

        /// <summary>
        /// Registers the specified <paramref name="user"/> in Cognito,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return CreateAsync(user, null, cancellationToken);
        }

        /// <summary>
        /// Registers the specified <paramref name="user"/> in Cognito,
        /// as an asynchronous operation. Also submits the validation data to the pre sign-up lambda trigger.
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <param name="validationData">The validation data to be sent to the pre sign-up lambda triggers.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> CreateAsync(TUser user, IDictionary<string, string> validationData, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                await _pool.AdminSignupAsync(user.UserID, user.Attributes, validationData).ConfigureAwait(false);
                return IdentityResult.Success;
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                return IdentityResult.Failed(_errorDescribers.CognitoServiceError("Failed to create the Cognito User", e));
            }
        }

        /// <summary>
        /// Deletes the specified <paramref name="user"/> from the user store.
        /// </summary>
        /// <param name="user">The user to delete.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
        public virtual async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                await _cognitoClient.AdminDeleteUserAsync(new AdminDeleteUserRequest
                {
                    Username = user.Username,
                    UserPoolId = _pool.PoolID
                }, cancellationToken).ConfigureAwait(false);

                return IdentityResult.Success;
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                return IdentityResult.Failed(_errorDescribers.CognitoServiceError("Failed to delete the Cognito User", e));
            }
        }

        /// <summary>
        /// Finds and returns a user, if any, who has the specified normalized user name.
        /// </summary>
        /// <param name="normalizedUserName">The normalized user name to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="normalizedUserName"/> if it exists.
        /// </returns>
        public virtual Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            return FindByIdAsync(normalizedUserName, cancellationToken);
        }

        public Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            throw new NotSupportedException("Cognito is case-sensitive and does not support normalized user name");
        }

        public Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken)
        {
            throw new NotSupportedException("Cognito is case-sensitive and does not support normalized user name");
        }

        public Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
        {
            throw new NotSupportedException("Cognito does not allow changing username, but the preferred_username attribute is allowed to change");
        }

        /// <summary>
        /// Updates the specified <paramref name="user"/> attributes in the user store.
        /// </summary>
        /// <param name="user">The user to update attributes for.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
        public virtual async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            try
            {
                // Only update user writable attributes.
                var clientConfig = await _pool.GetUserPoolClientConfiguration().ConfigureAwait(false);
                var newValues = clientConfig.WriteAttributes
                    .Where(key => user.Attributes.ContainsKey(key))
                    .ToDictionary(key => key, key => user.Attributes[key]);

                await _cognitoClient.AdminUpdateUserAttributesAsync(new AdminUpdateUserAttributesRequest
                {
                    UserAttributes = CreateAttributeList(newValues),
                    Username = user.Username,
                    UserPoolId = _pool.PoolID
                }, cancellationToken).ConfigureAwait(false);

                return IdentityResult.Success;
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                return IdentityResult.Failed(_errorDescribers.CognitoServiceError("Failed to update the Cognito User", e));
            }
        }

        /// <summary>
        /// Internal method to convert a dictionary of user attributes to a list of AttributeType
        /// </summary>
        /// <param name="attributeDict">Dictionary containing attributes of type string</param>
        /// <returns>Returns a List of AttributeType objects</returns>
        internal List<AttributeType> CreateAttributeList(IDictionary<string, string> attributeDict)
        {
            List<AttributeType> attributeList = new List<AttributeType>();
            foreach (KeyValuePair<string, string> data in attributeDict)
            {
                AttributeType attribute = new AttributeType()
                {
                    Name = data.Key,
                    Value = data.Value
                };

                attributeList.Add(attribute);
            }
            return attributeList;
        }

        #endregion

        #region IUserRoleStore

        /// <summary>
        /// Add the specified <paramref name="user"/> to the named role.
        /// </summary>
        /// <param name="user">The user to add to the named role.</param>
        /// <param name="roleName">The name of the role to add the user to.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public virtual Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            try
            {
                return _cognitoClient.AdminAddUserToGroupAsync(new AdminAddUserToGroupRequest
                {
                    GroupName = roleName,
                    Username = user.Username,
                    UserPoolId = _pool.PoolID
                }, cancellationToken);
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                throw new CognitoServiceException("Failed to add the Cognito User to a role", e);
            }
        }

        /// <summary>
        /// Remove the specified <paramref name="user"/> from the named role.
        /// </summary>
        /// <param name="user">The user to remove the named role from.</param>
        /// <param name="roleName">The name of the role to remove.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public virtual Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            try
            {
                return _cognitoClient.AdminRemoveUserFromGroupAsync(new AdminRemoveUserFromGroupRequest
                {
                    GroupName = roleName,
                    Username = user.Username,
                    UserPoolId = _pool.PoolID
                }, cancellationToken);
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                throw new CognitoServiceException("Failed to remove the Cognito User from a role", e);
            }
        }

        /// <summary>
        /// Gets a list of role names the specified <paramref name="user"/> belongs to.
        /// </summary>
        /// <param name="user">The user whose role names to retrieve.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a list of role names.</returns>
        public virtual async Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            try
            {
                // This calls retrieve ALL the groups
                var response = await _cognitoClient.AdminListGroupsForUserAsync(new AdminListGroupsForUserRequest
                {
                    Username = user.Username,
                    UserPoolId = _pool.PoolID
                }, cancellationToken).ConfigureAwait(false);

                return response.Groups.Select(group => group.GroupName).ToList();
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                throw new CognitoServiceException("Failed to retrieve roles for the Cognito User", e);
            }
        }

        /// <summary>
        /// Returns a flag indicating whether the specified <paramref name="user"/> is a member of the given named role.
        /// </summary>
        /// <param name="user">The user whose role membership should be checked.</param>
        /// <param name="roleName">The name of the role to be checked.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing a flag indicating whether the specified <paramref name="user"/> is
        /// a member of the named role.
        /// </returns>
        public virtual async Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var userRoles = await GetRolesAsync(user, cancellationToken).ConfigureAwait(false);
            return userRoles.Contains(roleName);
        }

        /// <summary>
        /// Returns a list of Users who are members of the named role.
        /// </summary>
        /// <param name="roleName">The name of the role whose membership should be returned.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing a list of users who are in the named role.
        /// </returns>
        public virtual async Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                // This calls retrieve ALL the user for a group
                var response = await _cognitoClient.ListUsersInGroupAsync(new ListUsersInGroupRequest
                {
                    GroupName = roleName,
                    UserPoolId = _pool.PoolID
                }, cancellationToken).ConfigureAwait(false);

                return response.Users.Select(user => _pool.GetUser(user.Username, user.UserStatus,
                    user.Attributes.ToDictionary(att => att.Name, att => att.Value))).ToList() as IList<TUser>;
            }
            catch (AmazonCognitoIdentityProviderException e)
            {
                throw new CognitoServiceException("Failed to get the Cognito Users in a role", e);
            }
        }
        #endregion
    }
}
