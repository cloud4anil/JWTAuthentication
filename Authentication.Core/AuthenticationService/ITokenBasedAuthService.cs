using AuthenticationProvider.Core.Model;
using System.Threading.Tasks;

namespace AuthenticationProvider.Core.AuthenticationService
{
    public interface ITokenBasedAuthService
    {
        Task<AuthToken> TokenAsync(string userName, string password);
        Task<AuthToken> RefreshTokenAsync(string token,string refreshToken);
    }
}
