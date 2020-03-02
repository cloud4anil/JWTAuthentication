namespace WebApi.JWT.Controllers
{
    using System.Threading.Tasks;
    using AuthenticationProvider.Core.AuthenticationService;
    using AuthenticationProvider.Core.Model;
    using Microsoft.AspNetCore.Mvc;

    [Route("api/[controller]/[action]")]
    public class TokenController : Controller
    {
        private readonly ITokenBasedAuthService _tokenBaseAuthService;
        public TokenController(ITokenBasedAuthService tokenBaseAuthService)
        {
            _tokenBaseAuthService = tokenBaseAuthService;
        }
        [HttpPost]
        public async Task<AuthToken> AuthToken(string username, string password)
        {
            var result = await _tokenBaseAuthService.TokenAsync(username, password);
            return result;
        }

        [HttpPost]
        public async Task<AuthToken>  RefreshToken(string token, string refreshToken)
        {
            var result = await _tokenBaseAuthService.RefreshTokenAsync(token, refreshToken);
            return result;
        }

    }
}