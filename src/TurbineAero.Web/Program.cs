using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using QRCoder;
using TurbineAero.Core.DTOs;
using TurbineAero.Data;
using TurbineAero.Data.Models;
using TurbineAero.Core.Interfaces;
using TurbineAero.Services;

const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

static string FormatKey(string unformattedKey)
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

static string GenerateQrCodeUri(string issuer, string email, string unformattedKey, UrlEncoder urlEncoder)
{
    return string.Format(
        AuthenticatorUriFormat,
        urlEncoder.Encode(issuer),
        urlEncoder.Encode(email),
        unformattedKey);
}

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

// Add Entity Framework
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"), 
        b => b.MigrationsAssembly("TurbineAero.Web")));

// Add Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 6;
    options.Password.RequiredUniqueChars = 1;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // User settings
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Register services
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<ISmsService, SmsService>();
builder.Services.AddScoped<IOtpService, OtpService>();
builder.Services.AddScoped<IFileStorageService, FtpFileStorageService>();

// Add HTTP client for API calls
builder.Services.AddHttpClient();

var app = builder.Build();

// Configure URLs for different ports
app.Urls.Add("http://localhost:7000");
app.Urls.Add("https://localhost:7001");

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapRazorPages();

var accountApi = app.MapGroup("/api/account").RequireAuthorization();

accountApi.MapGet("/preferences", async (ClaimsPrincipal principal, UserManager<ApplicationUser> userManager) =>
{
    var user = await userManager.GetUserAsync(principal);
    if (user == null)
    {
        return Results.Json(ApiResponse<object>.ErrorResult("User session has expired."), statusCode: StatusCodes.Status401Unauthorized);
    }

    var theme = string.IsNullOrWhiteSpace(user.ThemePreference) ? "light" : user.ThemePreference;
    return Results.Json(ApiResponse<object>.SuccessResult(new { theme }));
});

accountApi.MapPatch("/preferences", async ([FromBody] UpdateUserPreferencesRequest request, ClaimsPrincipal principal, UserManager<ApplicationUser> userManager) =>
{
    var theme = (request?.Theme ?? "light").ToLowerInvariant();
    if (theme != "light" && theme != "dark")
    {
        return Results.Json(ApiResponse<object>.ErrorResult("Invalid preference values."), statusCode: StatusCodes.Status400BadRequest);
    }

    var user = await userManager.GetUserAsync(principal);
    if (user == null)
    {
        return Results.Json(ApiResponse<object>.ErrorResult("User session has expired."), statusCode: StatusCodes.Status401Unauthorized);
    }

    user.ThemePreference = theme;
    var result = await userManager.UpdateAsync(user);
    if (!result.Succeeded)
    {
        var errors = result.Errors.Select(e => e.Description).ToList();
        return Results.Json(ApiResponse<object>.ErrorResult("Failed to update preferences.", errors), statusCode: StatusCodes.Status500InternalServerError);
    }

    return Results.Json(ApiResponse<object>.SuccessResult(new { theme }, "Preferences updated."));
});

accountApi.MapGet("/2fa-status", async (ClaimsPrincipal principal, UserManager<ApplicationUser> userManager) =>
{
    var user = await userManager.GetUserAsync(principal);
    if (user == null)
    {
        return Results.Json(ApiResponse<object>.ErrorResult("User session has expired."), statusCode: StatusCodes.Status401Unauthorized);
    }

    var enabled = await userManager.GetTwoFactorEnabledAsync(user);
    return Results.Json(ApiResponse<object>.SuccessResult(new { enabled }));
});

accountApi.MapPost("/enable-2fa", async (ClaimsPrincipal principal, UserManager<ApplicationUser> userManager, UrlEncoder urlEncoder, IConfiguration configuration) =>
{
    var user = await userManager.GetUserAsync(principal);
    if (user == null)
    {
        return Results.Json(ApiResponse<object>.ErrorResult("User session has expired."), statusCode: StatusCodes.Status401Unauthorized);
    }

    await userManager.SetTwoFactorEnabledAsync(user, false);

    var key = await userManager.GetAuthenticatorKeyAsync(user);
    if (string.IsNullOrWhiteSpace(key))
    {
        await userManager.ResetAuthenticatorKeyAsync(user);
        key = await userManager.GetAuthenticatorKeyAsync(user);
    }

    if (string.IsNullOrWhiteSpace(key))
    {
        return Results.Json(ApiResponse<object>.ErrorResult("Unable to generate an authenticator key."), statusCode: StatusCodes.Status500InternalServerError);
    }

    var email = user.Email ?? user.UserName ?? "user";
    var issuer = configuration["App:Name"] ?? "TurbineAero";
    var sharedKey = FormatKey(key);
    var authenticatorUri = GenerateQrCodeUri(issuer, email, key, urlEncoder);
    var qrCodeImageUrl = $"/api/account/qrcode?uri={Uri.EscapeDataString(authenticatorUri)}";

    return Results.Json(ApiResponse<object>.SuccessResult(new
    {
        secretKey = sharedKey,
        qrCodeUri = authenticatorUri,
        qrCodeImageUrl
    }, "Authenticator key generated."));
});

// Server-side QR code generation endpoint
accountApi.MapGet("/qrcode", (string uri) =>
{
    if (string.IsNullOrWhiteSpace(uri))
    {
        return Results.BadRequest("URI parameter is required");
    }

    try
    {
        using var qrGenerator = new QRCodeGenerator();
        var qrCodeData = qrGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
        using var qrCode = new PngByteQRCode(qrCodeData);
        // Generate QR code with minimal quiet zone by using drawQuietZones = false
        var qrCodeBytes = qrCode.GetGraphic(20, System.Drawing.Color.Black, System.Drawing.Color.White, false);

        return Results.File(qrCodeBytes, "image/png");
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed to generate QR code: {ex.Message}");
    }
});

accountApi.MapPost("/verify-2fa", async ([FromBody] VerifyTwoFactorRequest request, ClaimsPrincipal principal, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager) =>
{
    var code = request?.Code?.Trim();
    if (string.IsNullOrWhiteSpace(code) || code.Length != 6)
    {
        return Results.Json(ApiResponse<object>.ErrorResult("Invalid verification code."), statusCode: StatusCodes.Status400BadRequest);
    }

    var user = await userManager.GetUserAsync(principal);
    if (user == null)
    {
        return Results.Json(ApiResponse<object>.ErrorResult("User session has expired."), statusCode: StatusCodes.Status401Unauthorized);
    }

    var verificationCode = code.Replace(" ", string.Empty).Replace("-", string.Empty);
    var isTokenValid = await userManager.VerifyTwoFactorTokenAsync(user, userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

    if (!isTokenValid)
    {
        return Results.Json(ApiResponse<object>.ErrorResult("Invalid code. Please try again."), statusCode: StatusCodes.Status400BadRequest);
    }

    await userManager.SetTwoFactorEnabledAsync(user, true);
    await signInManager.RefreshSignInAsync(user);

    return Results.Json(ApiResponse<object>.SuccessResult(new { success = true }, "Two-factor authentication enabled."));
});

accountApi.MapPost("/disable-2fa", async (ClaimsPrincipal principal, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager) =>
{
    var user = await userManager.GetUserAsync(principal);
    if (user == null)
    {
        return Results.Json(ApiResponse<object>.ErrorResult("User session has expired."), statusCode: StatusCodes.Status401Unauthorized);
    }

    await userManager.SetTwoFactorEnabledAsync(user, false);
    await userManager.ResetAuthenticatorKeyAsync(user);
    await signInManager.RefreshSignInAsync(user);

    return Results.Json(ApiResponse<object>.SuccessResult(new { success = true }, "Two-factor authentication disabled."));
});

// Registration endpoints (no authentication required)
var registerApi = app.MapGroup("/api/auth/register");

// Rate limiting storage for registration (in-memory, simple implementation)
var registerOtpAttempts = new Dictionary<string, (int attempts, DateTime lockUntil)>();

registerApi.MapPost("/send-email-otp", async ([FromBody] SendEmailOtpRequest request, UserManager<ApplicationUser> userManager, IOtpService otpService, IEmailService emailService, ApplicationDbContext context, IConfiguration configuration, ILogger<Program> logger) =>
{
    if (request == null || string.IsNullOrWhiteSpace(request.Email))
    {
        return Results.Json(ApiResponse<object>.ErrorResult("Email is required."), statusCode: StatusCodes.Status400BadRequest);
    }

    var email = request.Email.Trim().ToLowerInvariant();

    // Check if user already exists
    var existingUser = await userManager.FindByEmailAsync(email);
    if (existingUser != null)
    {
        return Results.Json(ApiResponse<object>.ErrorResult("An account with this email already exists."), statusCode: StatusCodes.Status400BadRequest);
    }

    // Check rate limiting
    if (registerOtpAttempts.TryGetValue(email, out var attemptInfo))
    {
        if (attemptInfo.lockUntil > DateTime.UtcNow)
        {
            var remainingSeconds = (int)(attemptInfo.lockUntil - DateTime.UtcNow).TotalSeconds;
            return Results.Json(ApiResponse<object>.ErrorResult($"Too many failed attempts. Please wait {remainingSeconds} seconds and try again."), statusCode: StatusCodes.Status429TooManyRequests);
        }
    }

    // Check for recent OTP
    var recentOtp = await context.OtpLogs
        .Where(o => o.Identifier == email && o.OtpType == TurbineAero.Core.Interfaces.OtpType.Email.ToString())
        .OrderByDescending(o => o.CreatedAt)
        .FirstOrDefaultAsync();

    if (recentOtp != null && !recentOtp.IsUsed)
    {
        var secondsSinceLastOtp = (DateTime.UtcNow - recentOtp.CreatedAt).TotalSeconds;
        if (secondsSinceLastOtp < TurbineAero.Core.Constants.AppConstants.OtpResendCooldownSeconds)
        {
            var waitSeconds = Math.Max(1, TurbineAero.Core.Constants.AppConstants.OtpResendCooldownSeconds - (int)secondsSinceLastOtp);
            return Results.Json(ApiResponse<object>.ErrorResult($"Please wait {waitSeconds} seconds before requesting a new OTP."), statusCode: StatusCodes.Status400BadRequest);
        }

        if (recentOtp.ExpiresAt <= DateTime.UtcNow)
        {
            context.OtpLogs.Remove(recentOtp);
            await context.SaveChangesAsync();
        }
    }

    try
    {
        var code = await otpService.GenerateOtpAsync(email, TurbineAero.Core.Interfaces.OtpType.Email);
        var sent = await emailService.SendOtpEmailAsync(email, code);

        if (!sent)
        {
            var env = configuration["ASPNETCORE_ENVIRONMENT"];
            if (!string.Equals(env, "Development", StringComparison.OrdinalIgnoreCase))
            {
                return Results.Json(ApiResponse<object>.ErrorResult("Failed to send OTP. Please try again."), statusCode: StatusCodes.Status500InternalServerError);
            }

            logger.LogWarning("OTP email send failed but continuing because environment is Development for {Email}", email);
        }

        return Results.Json(ApiResponse<object>.SuccessResult(new { }, "OTP sent successfully."));
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error sending email OTP for {Email}", email);
        return Results.Json(ApiResponse<object>.ErrorResult("An error occurred while sending the OTP."), statusCode: StatusCodes.Status500InternalServerError);
    }
});

registerApi.MapPost("/verify-email-otp", async ([FromBody] VerifyEmailOtpRequest request, IOtpService otpService, ILogger<Program> logger) =>
{
    if (request == null || string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Otp))
    {
        return Results.Json(ApiResponse<object>.ErrorResult("Email and OTP are required."), statusCode: StatusCodes.Status400BadRequest);
    }

    var email = request.Email.Trim().ToLowerInvariant();
    var otp = request.Otp.Trim().Replace(" ", "").Replace("-", "");

    try
    {
        var verified = await otpService.VerifyOtpAsync(email, otp, TurbineAero.Core.Interfaces.OtpType.Email);
        if (!verified)
        {
            return Results.Json(ApiResponse<object>.ErrorResult("Invalid OTP."), statusCode: StatusCodes.Status400BadRequest);
        }

        return Results.Json(ApiResponse<object>.SuccessResult(new { }, "Email verified."));
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error verifying email OTP for {Email}", email);
        return Results.Json(ApiResponse<object>.ErrorResult("An error occurred during OTP verification."), statusCode: StatusCodes.Status500InternalServerError);
    }
});

// Login 2FA endpoints (no authentication required)
var login2FAApi = app.MapGroup("/api/auth/login-2fa");

// Rate limiting storage (in-memory, simple implementation)
var login2FAAttempts = new Dictionary<string, (int attempts, DateTime lockUntil)>();

login2FAApi.MapPost("/send-otp", async ([FromBody] Login2FASendOtpRequest request, UserManager<ApplicationUser> userManager, IOtpService otpService, IEmailService emailService) =>
{
    if (request == null || string.IsNullOrWhiteSpace(request.Email))
    {
        return Results.Json(ApiResponse<object>.ErrorResult("Email is required."), statusCode: StatusCodes.Status400BadRequest);
    }

    var email = request.Email.Trim().ToLowerInvariant();
    
    // Check rate limiting
    if (login2FAAttempts.TryGetValue(email, out var attemptInfo))
    {
        if (attemptInfo.lockUntil > DateTime.UtcNow)
        {
            var remainingSeconds = (int)(attemptInfo.lockUntil - DateTime.UtcNow).TotalSeconds;
            return Results.Json(ApiResponse<object>.ErrorResult($"Too many failed attempts. Please wait {remainingSeconds} seconds and try again."), statusCode: StatusCodes.Status429TooManyRequests);
        }
    }

    var user = await userManager.FindByEmailAsync(email);
    if (user == null)
    {
        return Results.Json(ApiResponse<object>.ErrorResult("Invalid email address."), statusCode: StatusCodes.Status400BadRequest);
    }

    var has2FA = await userManager.GetTwoFactorEnabledAsync(user);
    if (!has2FA)
    {
        return Results.Json(ApiResponse<object>.ErrorResult("Two-factor authentication is not enabled for this account."), statusCode: StatusCodes.Status400BadRequest);
    }

    try
    {
        var otp = await otpService.GenerateOtpAsync(email, TurbineAero.Core.Interfaces.OtpType.Email);
        var sent = await emailService.SendOtpEmailAsync(email, otp);
        
        if (!sent)
        {
            return Results.Json(ApiResponse<object>.ErrorResult("Failed to send OTP email."), statusCode: StatusCodes.Status500InternalServerError);
        }

        return Results.Json(ApiResponse<object>.SuccessResult(new { }, "OTP sent to your registered email."));
    }
    catch
    {
        return Results.Json(ApiResponse<object>.ErrorResult("An error occurred while sending OTP."), statusCode: StatusCodes.Status500InternalServerError);
    }
});

login2FAApi.MapPost("/verify", async ([FromBody] Login2FAVerifyRequest request, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IOtpService otpService, ApplicationDbContext context) =>
{
    if (request == null || string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Code))
    {
        return Results.Json(ApiResponse<object>.ErrorResult("Email and code are required."), statusCode: StatusCodes.Status400BadRequest);
    }

    var email = request.Email.Trim().ToLowerInvariant();
    var code = request.Code.Trim().Replace(" ", "").Replace("-", "");

    // Check rate limiting
    if (login2FAAttempts.TryGetValue(email, out var attemptInfo))
    {
        if (attemptInfo.lockUntil > DateTime.UtcNow)
        {
            var remainingSeconds = (int)(attemptInfo.lockUntil - DateTime.UtcNow).TotalSeconds;
            return Results.Json(ApiResponse<object>.ErrorResult($"Too many failed attempts. Please wait {remainingSeconds} seconds and try again."), statusCode: StatusCodes.Status429TooManyRequests);
        }
    }

    var user = await userManager.FindByEmailAsync(email);
    if (user == null)
    {
        return Results.Json(ApiResponse<object>.ErrorResult("Invalid email address."), statusCode: StatusCodes.Status400BadRequest);
    }

    var has2FA = await userManager.GetTwoFactorEnabledAsync(user);
    if (!has2FA)
    {
        return Results.Json(ApiResponse<object>.ErrorResult("Two-factor authentication is not enabled for this account."), statusCode: StatusCodes.Status400BadRequest);
    }

    bool isValid = false;

    if (request.Method == "authenticator")
    {
        // Verify authenticator app code
        isValid = await userManager.VerifyTwoFactorTokenAsync(user, userManager.Options.Tokens.AuthenticatorTokenProvider, code);
    }
    else if (request.Method == "email")
    {
        // Verify email OTP (5 minute expiration)
        isValid = await otpService.VerifyOtpAsync(email, code, TurbineAero.Core.Interfaces.OtpType.Email);
    }
    else
    {
        return Results.Json(ApiResponse<object>.ErrorResult("Invalid verification method."), statusCode: StatusCodes.Status400BadRequest);
    }

    if (!isValid)
    {
        // Increment failed attempts
        if (!login2FAAttempts.ContainsKey(email))
        {
            login2FAAttempts[email] = (0, DateTime.MinValue);
        }

        var attempts = login2FAAttempts[email].attempts + 1;
        var lockUntil = attempts >= 3 ? DateTime.UtcNow.AddSeconds(60) : DateTime.MinValue;
        login2FAAttempts[email] = (attempts, lockUntil);

        if (attempts >= 3)
        {
            return Results.Json(ApiResponse<object>.ErrorResult("Too many failed attempts. Please wait 60 seconds and try again."), statusCode: StatusCodes.Status429TooManyRequests);
        }

        return Results.Json(ApiResponse<object>.ErrorResult("Invalid code. Please try again."), statusCode: StatusCodes.Status400BadRequest);
    }

    // Reset failed attempts on success
    login2FAAttempts.Remove(email);

    // Sign in the user
    await signInManager.SignInAsync(user, isPersistent: false);
    
    // Update last login
    user.LastLoginAt = DateTime.UtcNow;
    await userManager.UpdateAsync(user);

    return Results.Json(ApiResponse<object>.SuccessResult(new { success = true }, "Verification successful!"));
});

// Ensure database is created
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    context.Database.EnsureCreated();
}

app.Run();
