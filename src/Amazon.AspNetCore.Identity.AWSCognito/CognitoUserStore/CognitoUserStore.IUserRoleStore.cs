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

using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Amazon.AspNetCore.Identity.AWSCognito
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
        public async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // The userId can be the userName, the email or the phone number depending on the User Pool login policy
            var user = await _pool.FindByIdAsync(userId).ConfigureAwait(false);
            return user as TUser;
        }

        /// <summary>
        /// Returns the userId associated with the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to retrieve the id for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the userId belonging to the matching the specified <paramref name="userId"/>.
        /// </returns>
        public Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
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
        public Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
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
        public Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
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
        public async Task<IdentityResult> CreateAsync(TUser user, IDictionary<string, string> validationData, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await _pool.AdminSignupAsync(user.UserID, user.Attributes, validationData).ConfigureAwait(false);
            return IdentityResult.Success;
        }

        public Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException("Cognito is case-sensitive and does not support normalized user name");
        }

        public Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException("Cognito is case-sensitive and does not support normalized user name");
        }

        public Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException("Cognito is case-sensitive and does not support normalized user name");
        }

        public Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException("Cognito does not allow changing username, but the preferred_username attribute is allowed to change");
        }

        /// <summary>
        /// Updates the specified <paramref name="user"/> attributes in the user store.
        /// </summary>
        /// <param name="user">The user to update attributes for.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
        public async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            // Only update user writable attributes.
            var clientConfig = await _pool.GetUserPoolClientConfiguration().ConfigureAwait(false);
            var newValues = clientConfig.WriteAttributes
                .Where(key => user.Attributes.ContainsKey(key))
                .ToDictionary(key => key, key => user.Attributes[key]);

            await _provider.AdminUpdateUserAttributesAsync(new AdminUpdateUserAttributesRequest
            {
                UserAttributes = CreateAttributeList(newValues),
                Username = user.Username,
                UserPoolId = _pool.PoolID
            }).ConfigureAwait(false);

            return IdentityResult.Success;
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

        // Roles Handling:
        public Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            //WIP: AdminAddUserToGroupAsync
            throw new NotImplementedException();
        }

        public Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            //WIP: AdminRemoveUserFromGroupAsync
            throw new NotImplementedException();
        }

        public Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken)
        {
            //WIP: ListGroupsAsync
            throw new NotImplementedException();
        }

        public Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            //WIP: AdminListGroupsForUserAsync
            throw new NotImplementedException();
        }

        public Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            //WIP: ListUsersInGroupAsync
            throw new NotImplementedException();
        }
        #endregion
    }
}
