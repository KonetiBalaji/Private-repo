using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using TurbineAero.Data.Models;
using TurbineAero.Core.Interfaces;
using TurbineAero.Data;

namespace TurbineAero.Web.Pages.Account;

public class RegisterModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<RegisterModel> _logger;
    private readonly ApplicationDbContext _context;
    private readonly IEmailService _emailService;

    public RegisterModel(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ILogger<RegisterModel> logger,
        ApplicationDbContext context,
        IEmailService emailService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
        _context = context;
        _emailService = emailService;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? ReturnUrl { get; set; }

    public class InputModel
    {
        [Required]
        [StringLength(50)]
        [Display(Name = "First Name")]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [StringLength(50)]
        [Display(Name = "Last Name")]
        public string LastName { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        [Required]
        [StringLength(12, ErrorMessage = "The {0} must be between {2} and {1} characters long.", MinimumLength = 8)]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,12}$", ErrorMessage = "Password must be 8-12 characters long and include letters, numbers, and special characters.")]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public void OnGetAsync(string? returnUrl = null)
    {
        ReturnUrl = returnUrl;
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");
        
        if (ModelState.IsValid)
        {
            var normalizedEmail = Input.Email.Trim().ToLowerInvariant();

            var emailOtp = await _context.OtpLogs
                .Where(o => o.Identifier == normalizedEmail &&
                            o.OtpType == OtpType.Email.ToString())
                .OrderByDescending(o => o.CreatedAt)
                .FirstOrDefaultAsync();

            if (emailOtp == null || !emailOtp.IsUsed || emailOtp.ExpiresAt < DateTime.UtcNow)
            {
                ModelState.AddModelError(string.Empty, "Please verify your email before creating an account.");
                return Page();
            }

            var user = new ApplicationUser 
            { 
                UserName = normalizedEmail, 
                Email = normalizedEmail,
                FirstName = Input.FirstName,
                LastName = Input.LastName
            };
            
            var result = await _userManager.CreateAsync(user, Input.Password);
            if (result.Succeeded)
            {
                _logger.LogInformation("User created a new account with password.");

                var otpLogs = await _context.OtpLogs
                    .Where(o => o.Identifier == normalizedEmail && o.OtpType == OtpType.Email.ToString())
                    .ToListAsync();
                if (otpLogs.Any())
                {
                    _context.OtpLogs.RemoveRange(otpLogs);
                    await _context.SaveChangesAsync();
                }
                
                // Send welcome email
                try
                {
                    await _emailService.SendWelcomeEmailAsync(normalizedEmail, Input.FirstName);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to send welcome email to {Email}", normalizedEmail);
                    // Continue even if email fails
                }
                
                await _signInManager.SignInAsync(user, isPersistent: false);
                
                // Return success flag for frontend to show modal
                TempData["RegistrationSuccess"] = true;
                TempData["UserFirstName"] = Input.FirstName;
                return Page();
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        return Page();
    }
}
