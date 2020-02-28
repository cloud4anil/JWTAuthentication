namespace AuthenticationProvider.Core.AuthenticationService
{

    using AuthenticationProvider.Core.Model;
    using Microsoft.IdentityModel.Tokens;
    using System;
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using System.Security.Claims;
    using System.Text;
    using System.Collections.Generic;
    using AuthenticationProvider.Core.UserService;
    using System.Security.Cryptography;
    using Microsoft.Extensions.Configuration;
    public class JWTAuthService : ITokenBasedAuthService
    {
       
        private readonly IUserService _authRepository;
        private readonly IConfiguration _configuration;
        public JWTAuthService(IUserService authRepository, IConfiguration configuration)
        {
            _authRepository = authRepository;
            _configuration = configuration;
        }

        /// <summary>
        /// Token
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public AuthToken Token(string userName, string password)
        {
           var user = _authRepository.ValidateUser(userName, password).FirstOrDefault();
           if(user!=null)
            {
                string token = GenerateToken(user);
                var refreshToken = GenerateRefreshToken();
                _authRepository.AddSecuirtyToken(new UserAuthToken { UserName = user.UserName, RefreshToken = refreshToken });
                return new AuthToken { AccessToken = token, RefreshToken = refreshToken };
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// RefreshToken
        /// </summary>
        /// <param name="token"></param>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        public AuthToken RefreshToken(string token,string refreshToken)
        {
            var principal = GetPrincipalFromExpiredToken(token);
            var username = principal.Identity.Name;
            var user = _authRepository.GetUser(username).FirstOrDefault();
            var userToken = _authRepository.GetSecuirtyToken(username).FirstOrDefault();
            if (user != null && userToken.RefreshToken == refreshToken)
            {
                string newtoken = GenerateToken(user);
                var newRefreshToken = GenerateRefreshToken();
                _authRepository.AddSecuirtyToken(new UserAuthToken { UserName = user.UserName, RefreshToken = newRefreshToken });
                return new AuthToken { AccessToken = newtoken, RefreshToken = newRefreshToken };
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// GetUserClaims
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private IEnumerable<Claim> GetUserClaims(UserModel user)
        {
           //var role= user.Roles.Select(x => x.UserRole).Aggregate((current, next) => current + "," + next);
            var claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.Name, user.UserName));
            claims.Add(new Claim(ClaimTypes.Surname, user.LastName));
            foreach(var role in user.Roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role.UserRole.ToUpper()));
            }          
            ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, "Token");        
            claimsIdentity.AddClaims(user.Roles.Select(r => new Claim(ClaimTypes.Role, r.UserRole.ToUpper())));
            return claims;
        }

        /// <summary>
        /// GetPrincipalFromExpiredToken
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var key = Encoding.UTF8.GetBytes(Constants.Secret);
            var tokenValidationParameters =  new TokenValidationParameters
            {
                ValidateAudience = Convert.ToBoolean(_configuration["TokenParameters:ValidateAudience"]),
                ValidateIssuer =   Convert.ToBoolean(_configuration["TokenParameters:ValidateIssuer"]),
                ValidateIssuerSigningKey = Convert.ToBoolean(_configuration["TokenParameters:ValidateIssuerSigningKey"]),
                IssuerSigningKey = new SymmetricSecurityKey(key),
                             
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            JwtSecurityToken jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256Signature, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }


        /// <summary>
        ///  Generate refresh token key 
        /// </summary>
        /// <returns></returns>
        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        /// <summary>
        /// Generate user token key
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private string GenerateToken(UserModel user)
        {
            var key = Encoding.ASCII.GetBytes(Constants.Secret);
            //TODO configure data from Appsetting
            var JWToken = new JwtSecurityToken(
             issuer: _configuration["TokenParameters:Issuer"],
             audience: _configuration["TokenParameters:audience"],
             claims: GetUserClaims(user),
             notBefore: new DateTimeOffset(DateTime.Now).DateTime,
             expires: new DateTimeOffset(DateTime.Now.AddSeconds(60)).DateTime,
                //Using HS256 Algorithm to encrypt Token  
             signingCredentials: new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            );
           
            var token = new JwtSecurityTokenHandler().WriteToken(JWToken);
            return token;
        }
    }
}
