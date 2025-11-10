using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TurbineAero.Data.Models;

namespace TurbineAero.Web.Pages.Account;

public class LogoutModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<LogoutModel> _logger;

    public LogoutModel(SignInManager<ApplicationUser> signInManager, ILogger<LogoutModel> logger)
    {
        _signInManager = signInManager;
        _logger = logger;
    }

    public async Task<IActionResult> OnGet()
    {
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        await _signInManager.SignOutAsync();
        _logger.LogInformation("User logged out.");
        // Return the page which will handle localStorage clearing and redirect client-side
        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        return await OnGet();
    }
}

