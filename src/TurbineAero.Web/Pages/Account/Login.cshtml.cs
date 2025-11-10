using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace TurbineAero.Web.Pages.Account;

public class LoginModel : PageModel
{
    public IActionResult OnGet(string? returnUrl = null)
    {
        // If user is already authenticated, redirect to Dashboard
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToPage("/Dashboard");
        }
        return RedirectToPage("/Index", new { returnUrl });
    }

    public IActionResult OnPost(string? returnUrl = null)
    {
        return RedirectToPage("/Index", new { returnUrl });
    }
}
