using Microsoft.AspNet.Identity;
using Neo4jClient;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Neo4j.AspNet.Identity
{
    public class UserStore<TUser> : IUserLoginStore<TUser>, IUserClaimStore<TUser>, IUserRoleStore<TUser>,
       IUserPasswordStore<TUser>, IUserSecurityStampStore<TUser>, IUserStore<TUser>, IUserEmailStore<TUser>,
       IUserPhoneNumberStore<TUser>, IUserTwoFactorStore<TUser, string>
       where TUser : IdentityUser
    {
        private GraphClient db;

        protected GraphClient GraphDB
        {
            get { return db; }
            private set { db = value; }
        }

        private bool _disposed;

        private GraphClient GetGraphDatabaseFromUri(string serverUriOrName)
        {
            if (serverUriOrName.ToLower().Contains("http://"))
            {
                return new GraphClient(new Uri(serverUriOrName));
            }
            else
            {
                return new GraphClient(new Uri(ConfigurationManager.ConnectionStrings[serverUriOrName].ConnectionString));
            }
        }

        public UserStore()
            : this("DefaultConnection")
        {

        }

        public UserStore(string connectionNameOrUri)
        {
            GraphDB = GetGraphDatabaseFromUri(connectionNameOrUri);
            GraphDB.Connect();
        }

        public UserStore(GraphClient neoDb)
        {
            GraphDB = neoDb;
        }

        #region IUserLoginStore

        public virtual Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            if (!user.Logins.Any(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey))
            {
                user.Logins.Add(login);
            }

            return Task.FromResult(true);
        }

        public virtual Task<TUser> FindAsync(UserLoginInfo login)
        {
            throw new NotImplementedException();
        }

        public virtual Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult(user.Logins as IList<UserLoginInfo>);
        }

        public virtual Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.Logins.RemoveAll(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey);

            return Task.FromResult(0);
        }

        public virtual Task CreateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.Id = Guid.NewGuid().ToString();
            //db.GetCollection<TUser>(collectionName).Insert(user);

            GraphDB.Cypher.Create("(u:User { user })")
                                      .WithParams(new { user })
                                      .ExecuteWithoutResults();



            return Task.FromResult(user);
        }

        public virtual Task DeleteAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public virtual Task<TUser> FindByIdAsync(string userId)
        {
            ThrowIfDisposed();

            TUser user = GraphDB.Cypher
                      .Match("(u:User)")
                      .Where((TUser u) => u.Id == userId)
                      .Return(u => u.As<TUser>())
                      .Results
                      .SingleOrDefault();

            //   TUser user = db.GetCollection<TUser>(collectionName).FindOne((Query.EQ("_id", ObjectId.Parse(userId))));
            return Task.FromResult(user);
        }

        public virtual Task<TUser> FindByNameAsync(string userName)
        {
            ThrowIfDisposed();

            TUser user = GraphDB.Cypher
                        .Match("(u:User)")
                        .Where((TUser u) => u.UserName == userName)
                        .Return(u => u.As<TUser>())
                        .Results
                        .SingleOrDefault();


            // TUser user = db.GetCollection<TUser>(collectionName).FindOne((Query.EQ("UserName", userName)));
            return Task.FromResult(user);
        }

        public virtual Task UpdateAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public virtual void Dispose()
        {
            _disposed = true;
        }

        #endregion

        #region IUserClaimStore

        public virtual Task AddClaimAsync(TUser user, System.Security.Claims.Claim claim)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            if (!user.Claims.Any(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value))
            {
                user.Claims.Add(new IdentityUserClaim
                {
                    ClaimType = claim.Type,
                    ClaimValue = claim.Value
                });
            }


            return Task.FromResult(0);
        }

        public virtual Task<IList<System.Security.Claims.Claim>> GetClaimsAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            IList<Claim> result = user.Claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();
            return Task.FromResult(result);
        }

        public virtual Task RemoveClaimAsync(TUser user, System.Security.Claims.Claim claim)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.Claims.RemoveAll(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value);
            return Task.FromResult(0);
        }
        #endregion

        #region IUserRoleStore
        public virtual Task AddToRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            if (!user.Roles.Contains(roleName, StringComparer.InvariantCultureIgnoreCase))
                user.Roles.Add(roleName);

            return Task.FromResult(true);
        }

        public virtual Task<IList<string>> GetRolesAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult<IList<string>>(user.Roles);
        }

        public virtual Task<bool> IsInRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult(user.Roles.Contains(roleName, StringComparer.InvariantCultureIgnoreCase));
        }

        public virtual Task RemoveFromRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.Roles.RemoveAll(r => String.Equals(r, roleName, StringComparison.InvariantCultureIgnoreCase));

            return Task.FromResult(0);
        }
        #endregion

        #region IUserPasswordStore
        public virtual Task<string> GetPasswordHashAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult(user.PasswordHash);
        }

        public virtual Task<bool> HasPasswordAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult(user.PasswordHash != null);
        }

        public virtual Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        }
        #endregion

        #region IUserSecurityStampStore
        public virtual Task<string> GetSecurityStampAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult(user.SecurityStamp);
        }

        public virtual Task SetSecurityStampAsync(TUser user, string stamp)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.SecurityStamp = stamp;
            return Task.FromResult(0);
        }
        #endregion

        #region IUserEmailStore
        public virtual Task<TUser> FindByEmailAsync(string email)
        {
            ThrowIfDisposed();

            TUser user = GraphDB.Cypher
                      .Match("(u:User)")
                      .Where((TUser u) => u.Email == email)
                      .Return(u => u.As<TUser>())
                      .Results
                      .SingleOrDefault();

            //TUser user = db.GetCollection<TUser>(collectionName).FindOne((Query.EQ("email", email)));
            return Task.FromResult(user);
        }

        public virtual Task<string> GetEmailAsync(TUser user)
        {
            ThrowIfDisposed();
            string email = user.Email;

            if (string.IsNullOrWhiteSpace(email) && user.Id != null)
                email = GraphDB.Cypher
                          .Match("(u:User)")
                          .Where((TUser u) => u.Id == user.Id)
                          .Return(u => u.As<TUser>())
                          .Results
                          .SingleOrDefault()
                          .Email;

            //TUser user = db.GetCollection<TUser>(collectionName).FindOne((Query.EQ("email", email)));

            return Task.FromResult<string>(email);
        }

        public virtual Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            return Task.FromResult(user.Email != null);
        }

        public virtual async Task SetEmailAsync(TUser user, string email)
        {
            user.Email = email;
            await UpdateAsync(user);
        }

        public virtual async Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            // user.Email = email;
            await UpdateAsync(user);
        }
        #endregion

        protected void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);
        }

        public Task<string> GetPhoneNumberAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public async Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.PhoneNumber = phoneNumber;
            await UpdateAsync(user);
        }

        public async Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.PhoneNumberConfirmed = confirmed;
            await UpdateAsync(user);
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            return Task.FromResult(false);
        }

        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        { 
            return Task.FromResult(0);
        }
    }

}
