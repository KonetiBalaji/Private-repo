using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace TurbineAero.Web.Pages.Account;

public class ResetPasswordModel : PageModel
{
    private readonly ILogger<ResetPasswordModel> _logger;

    public ResetPasswordModel(ILogger<ResetPasswordModel> logger)
    {
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? Token { get; set; }
    public string? Email { get; set; }

    public class InputModel
    {
        [Required]
        [StringLength(12, ErrorMessage = "The {0} must be between {2} and {1} characters long.", MinimumLength = 8)]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,12}$", ErrorMessage = "Password must be 8-12 characters long and include letters, numbers, and special characters.")]
        [Display(Name = "New Password")]
        public string NewPassword { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password")]
        [Compare(nameof(NewPassword), ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public void OnGet(string? token = null, string? email = null)
    {
        Token = token ?? Request.Query["token"].ToString();
        Email = email ?? Request.Query["email"].ToString();

        if (string.IsNullOrWhiteSpace(Token) || string.IsNullOrWhiteSpace(Email))
        {
            ModelState.AddModelError(string.Empty, "Invalid reset link. Please request a new password reset.");
        }
    }

    public IActionResult OnPost()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        // The actual password reset is handled by the API via JavaScript
        // This method is kept for server-side validation if needed
        return Page();
    }
}

