using AuthenticationProvider.Core.Model;

namespace AuthenticationProvider.Core.AuthenticationService
{
    public interface ITokenBasedAuthService
    {
        AuthToken Token(string userName, string password);
        AuthToken RefreshToken(string token,string refreshToken);
    }
}
