using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TurbineAero.Core.Interfaces;

namespace TurbineAero.Web.Pages.Account;

public class ForgotPasswordModel : PageModel
{
    private readonly IEmailService _emailService;
    private readonly ILogger<ForgotPasswordModel> _logger;

    public ForgotPasswordModel(IEmailService emailService, ILogger<ForgotPasswordModel> logger)
    {
        _emailService = emailService;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public class InputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
    }

    public void OnGet()
    {
    }

    public IActionResult OnPost()
    {
        if (ModelState.IsValid)
        {
            // This would typically involve generating a reset token and sending an email
            // For now, we'll just show a success message
            _logger.LogInformation("Password reset requested for {Email}", Input.Email);
            
            TempData["Message"] = "If the email exists, a password reset link has been sent.";
            return Page();
        }

        return Page();
    }
}
