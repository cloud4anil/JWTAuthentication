using AuthenticationProvider.Core.Model;
using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticationProvider.Core.UserService
{
    public interface IUserService
    {
        IEnumerable<UserModel> ValidateUser(string userName, string password);
        IEnumerable<UserModel> GetUser(string userName);
        void AddSecuirtyToken(UserAuthToken userSecurityToken);
        IEnumerable<UserAuthToken> GetSecuirtyToken(string userName);
        void DeletSecuirtyToken(UserAuthToken userSecurityToken);
    }
}
