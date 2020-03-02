namespace AuthenticationProvider.Core.Filters
{
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Filters;
    using System.Security.Claims;
    public class ClaimAuthorizationAttribute : TypeFilterAttribute
    {
        
        public ClaimAuthorizationAttribute(params string[] claim) : base(typeof(AuthorizeFilter))
        {
            Arguments = new object[] { claim };
        }
    }

    public class AuthorizeFilter : IAuthorizationFilter
    {
        readonly string[] _claim;
        public AuthorizeFilter(params string[] claim)
        {
            _claim = claim;
        }
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var IsAuthenticated = context.HttpContext.User.Identity.IsAuthenticated;
            var claimsIndentity = context.HttpContext.User.Identity as ClaimsIdentity;
            if (IsAuthenticated)
            {
                bool flagClaim = false;
                foreach (var item in _claim)
                {
                    if (context.HttpContext.User.HasClaim(item, item))
                        flagClaim = true;
                }
                if (!flagClaim)
                {

                    // TODO
                    context.Result = new RedirectResult("~/Home/NoPermission");
                }
            }
            else
            {
                //TODO
               // context.Result = new RedirectResult("~/Home/Index");
            }
            return;
        }
    }
}
