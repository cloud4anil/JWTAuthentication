using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthenticationProvider.Core.AuthenticationService;
using AuthenticationProvider.Core.Model;
using Microsoft.AspNetCore.Mvc;

namespace WebApi.JWT.Controllers
{
    [Route("api/[controller]/[action]")]
    public class TokenController : Controller
    {
        private readonly ITokenBasedAuthService _tokenBaseAuthService;
        public TokenController(ITokenBasedAuthService tokenBaseAuthService)
        {
            _tokenBaseAuthService = tokenBaseAuthService;
        }
        [HttpPost]
        public async Task<AuthToken> PostAuthToken(string username, string password)
        {
            var result = _tokenBaseAuthService.Token(username, password);
            return result;
        }

        [HttpPost]
        public async Task<AuthToken> PostRefreshToken(string token, string refreshToken)
        {
            var result = _tokenBaseAuthService.RefreshToken(token, refreshToken);
            return result;
        }

    }
}