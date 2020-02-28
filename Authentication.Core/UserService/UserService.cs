using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AuthenticationProvider.Core.Model;

namespace AuthenticationProvider.Core.UserService
{
    public class UserService : IUserService
    {
        private readonly List<UserModel> _userModels;
        private readonly List<UserAuthToken> _userSecuirtyToken;
        public UserService()
        {
            _userModels = new List<UserModel>();
            _userSecuirtyToken = new List<UserAuthToken>();
            _userModels.Add(new UserModel {
                FirstName="Anil",
                LastName="Kumar",
                UserName ="anil",
                Password ="1234",
                Roles= new List<Role> { new Role { UserRole= Roles.READER }, new Role { UserRole= Roles.WRITTER} }
            }
                
                );

            _userModels.Add(new UserModel
            {
                FirstName = "Brijesh",
                LastName = "Singh",
                UserName = "brijesh",
                Password = "1234",
                Roles = new List<Role> { new Role { UserRole = Roles.ADMIN } }
            }

           );
        }
        public IEnumerable<UserModel> ValidateUser(string userName, string password)
        {
            return _userModels.Where(r => r.UserName == userName && r.Password == password);
        }

        public void AddSecuirtyToken(UserAuthToken userSecurityToken)
        {
            _userSecuirtyToken.Add(userSecurityToken);
        }

        public void DeletSecuirtyToken(UserAuthToken userSecurityToken)
        {
            _userSecuirtyToken.Remove(userSecurityToken);
        }

        public IEnumerable<UserModel> GetUser(string userName)
        {
            return _userModels.Where(r => r.UserName == userName );
        }

        public IEnumerable<UserAuthToken> GetSecuirtyToken(string userName)
        {
            return _userSecuirtyToken.Where(r => r.UserName == userName);
        }
    }
}
