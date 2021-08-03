using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Samples.Pages
{
    public class OAuthExampleModel : PageModel
    {
        UserManager<CognitoUser> _userManager;

        public string JwtToken { get; private set; }

        public bool IsLoggedIn { get; private set; }

        public OAuthExampleModel(UserManager<CognitoUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task OnGet()
        {
            var cognitoUser = await _userManager.GetUserAsync(this.HttpContext.User);
            IsLoggedIn = cognitoUser != null;
            if (IsLoggedIn)
            {
                this.JwtToken = cognitoUser.SessionTokens.IdToken;
            }
        }
    }
}
