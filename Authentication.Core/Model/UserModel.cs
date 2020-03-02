namespace AuthenticationProvider.Core.Model
{
    using System;
    using System.Collections.Generic;
    public class UserModel
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public List<Role> Roles { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }



    public class AuthToken
    {
        public string AccessToken { get; set; }       
        public string RefreshToken { get; set; }

    }

    public class UserAuthToken
    {
        public string UserName { get; set; }
        public DateTimeOffset AccessTokenExpiration { get; set; }
        public string RefreshToken { get; set; }

    }


    public class Role
    {
       public string UserRole { get; set; }
    }


    public static class Roles
    {
        public const string ADMIN = "ADMIN";
        public const string READER = "READER";
        public const string WRITTER = "WRITTER";
    }

    public static class Constants
    {
        public const string Secret = "this is my jwt secret key ";
    }
}
