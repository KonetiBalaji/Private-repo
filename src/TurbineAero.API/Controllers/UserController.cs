using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using TurbineAero.Core.DTOs;
using TurbineAero.Data.Models;

namespace TurbineAero.API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class UserController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UrlEncoder _urlEncoder;
    private readonly ILogger<UserController> _logger;
    private readonly IConfiguration _configuration;

    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

    public UserController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        UrlEncoder urlEncoder,
        ILogger<UserController> logger,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _urlEncoder = urlEncoder;
        _logger = logger;
        _configuration = configuration;
    }

    [HttpGet("2fa-status")]
    public async Task<ActionResult<ApiResponse<object>>> GetTwoFactorStatus()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return Unauthorized(ApiResponse<object>.ErrorResult("User session has expired."));
        }

        var enabled = await _userManager.GetTwoFactorEnabledAsync(user);
        return Ok(ApiResponse<object>.SuccessResult(new { enabled }));
    }

    [HttpPost("enable-2fa")]
    public async Task<ActionResult<ApiResponse<object>>> EnableTwoFactorAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return Unauthorized(ApiResponse<object>.ErrorResult("User session has expired."));
        }

        await _userManager.SetTwoFactorEnabledAsync(user, false);

        var key = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrWhiteSpace(key))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            key = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        if (string.IsNullOrWhiteSpace(key))
        {
            _logger.LogError("Failed to generate authenticator key for user {UserId}", user.Id);
            return StatusCode(500, ApiResponse<object>.ErrorResult("Unable to generate an authenticator key."));
        }

        var email = user.Email ?? user.UserName ?? "user";
        var issuer = _configuration["App:Name"] ?? "TurbineAero";
        var sharedKey = FormatKey(key);
        var authenticatorUri = GenerateQrCodeUri(issuer, email, key);
        var qrCodeImageUrl = $"https://chart.googleapis.com/chart?chs=220x220&chld=M|0&cht=qr&chl={Uri.EscapeDataString(authenticatorUri)}";

        return Ok(ApiResponse<object>.SuccessResult(new
        {
            secretKey = sharedKey,
            qrCodeUri = authenticatorUri,
            qrCodeImageUrl
        }, "Authenticator key generated."));
    }

    [HttpPost("verify-2fa")]
    public async Task<ActionResult<ApiResponse<object>>> VerifyTwoFactorAsync([FromBody] VerifyTwoFactorRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ApiResponse<object>.ErrorResult("Invalid verification code."));
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return Unauthorized(ApiResponse<object>.ErrorResult("User session has expired."));
        }

        var verificationCode = request.Code.Replace(" ", string.Empty).Replace("-", string.Empty);
        var isTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
            user,
            _userManager.Options.Tokens.AuthenticatorTokenProvider,
            verificationCode);

        if (!isTokenValid)
        {
            return BadRequest(ApiResponse<object>.ErrorResult("Invalid code. Please try again."));
        }

        await _userManager.SetTwoFactorEnabledAsync(user, true);
        await _signInManager.RefreshSignInAsync(user);
        _logger.LogInformation("Two-factor authentication enabled for user {UserId}", user.Id);

        return Ok(ApiResponse<object>.SuccessResult(new { success = true }, "Two-factor authentication enabled."));
    }

    [HttpPost("disable-2fa")]
    public async Task<ActionResult<ApiResponse<object>>> DisableTwoFactorAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return Unauthorized(ApiResponse<object>.ErrorResult("User session has expired."));
        }

        await _userManager.SetTwoFactorEnabledAsync(user, false);
        await _userManager.ResetAuthenticatorKeyAsync(user);
        await _signInManager.RefreshSignInAsync(user);
        _logger.LogInformation("Two-factor authentication disabled for user {UserId}", user.Id);

        return Ok(ApiResponse<object>.SuccessResult(new { success = true }, "Two-factor authentication disabled."));
    }

    [HttpGet("preferences")]
    public async Task<ActionResult<ApiResponse<object>>> GetPreferences()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return Unauthorized(ApiResponse<object>.ErrorResult("User session has expired."));
        }

        return Ok(ApiResponse<object>.SuccessResult(new
        {
            theme = string.IsNullOrWhiteSpace(user.ThemePreference) ? "light" : user.ThemePreference
        }));
    }

    [HttpPatch("preferences")]
    public async Task<ActionResult<ApiResponse<object>>> UpdatePreferences([FromBody] UpdateUserPreferencesRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ApiResponse<object>.ErrorResult("Invalid preference values."));
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return Unauthorized(ApiResponse<object>.ErrorResult("User session has expired."));
        }

        user.ThemePreference = request.Theme.ToLowerInvariant();
        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            var errors = result.Errors.Select(e => e.Description).ToList();
            return StatusCode(500, ApiResponse<object>.ErrorResult("Failed to update preferences.", errors));
        }

        return Ok(ApiResponse<object>.SuccessResult(new { theme = user.ThemePreference }, "Preferences updated."));
    }

    private string GenerateQrCodeUri(string issuer, string email, string unformattedKey)
    {
        return string.Format(
            AuthenticatorUriFormat,
            _urlEncoder.Encode(issuer),
            _urlEncoder.Encode(email),
            unformattedKey);
    }

    private static string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
        var currentPosition = 0;
        while (currentPosition + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition, 4)).Append(' ');
            currentPosition += 4;
        }
        result.Append(unformattedKey.AsSpan(currentPosition));
        return result.ToString().ToUpperInvariant();
    }
}
