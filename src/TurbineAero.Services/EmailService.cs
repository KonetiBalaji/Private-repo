using MailKit.Net.Smtp;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MimeKit;
using TurbineAero.Core.Constants;
using TurbineAero.Core.Interfaces;

namespace TurbineAero.Services;

public class EmailService : IEmailService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<EmailService> _logger;

    public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<bool> SendOtpEmailAsync(string email, string otp)
    {
        try
        {
            // If SMTP is not configured, simulate success for development/testing
            var smtpHost = _configuration["Email:SmtpHost"]; 
            var smtpPort = _configuration["Email:SmtpPort"]; 
            var smtpUser = _configuration["Email:Username"]; 
            var smtpPass = _configuration["Email:Password"]; 
            var fromAddress = _configuration["Email:FromAddress"]; 

            if (string.IsNullOrWhiteSpace(smtpHost) || string.IsNullOrWhiteSpace(smtpPort) ||
                string.IsNullOrWhiteSpace(smtpUser) || string.IsNullOrWhiteSpace(smtpPass) ||
                string.IsNullOrWhiteSpace(fromAddress))
            {
                _logger.LogWarning("SMTP not configured. Simulating OTP email delivery to {Email}.", email);
                return true; // simulate success
            }

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(AppConstants.Email.FromName, _configuration["Email:FromAddress"]));
            message.To.Add(new MailboxAddress("", email));
            message.Subject = AppConstants.Email.SubjectOtp;

            var bodyBuilder = new BodyBuilder
            {
                HtmlBody = $@"
                    <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
                        <h2 style='color: #333;'>Verification Code</h2>
                        <p>Your verification code is:</p>
                        <div style='background-color: #f4f4f4; padding: 20px; text-align: center; margin: 20px 0;'>
                            <h1 style='color: #007bff; font-size: 32px; margin: 0; letter-spacing: 5px;'>{otp}</h1>
                        </div>
                        <p>This code will expire in {AppConstants.OtpExpiryMinutes} minutes.</p>
                        <p>If you didn't request this code, please ignore this email.</p>
                    </div>"
            };

            message.Body = bodyBuilder.ToMessageBody();

            using var client = new SmtpClient();
            await client.ConnectAsync(smtpHost, int.Parse(smtpPort!), false);
            await client.AuthenticateAsync(smtpUser, smtpPass);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);

            _logger.LogInformation("OTP email sent successfully to {Email}", email);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send OTP email to {Email}", email);
            return false;
        }
    }

    public async Task<bool> SendPasswordResetEmailAsync(string email, string resetToken)
    {
        try
        {
            // If SMTP is not configured, simulate success for development/testing
            var smtpHost = _configuration["Email:SmtpHost"]; 
            var smtpPort = _configuration["Email:SmtpPort"]; 
            var smtpUser = _configuration["Email:Username"]; 
            var smtpPass = _configuration["Email:Password"]; 
            var fromAddress = _configuration["Email:FromAddress"]; 
            var env = _configuration["ASPNETCORE_ENVIRONMENT"] ?? Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Development";

            if (string.IsNullOrWhiteSpace(smtpHost) || string.IsNullOrWhiteSpace(smtpPort) ||
                string.IsNullOrWhiteSpace(smtpUser) || string.IsNullOrWhiteSpace(smtpPass) ||
                string.IsNullOrWhiteSpace(fromAddress))
            {
                _logger.LogWarning("SMTP not configured. Simulating password reset email delivery to {Email}. Reset token: {Token}", email, resetToken);
                return true; // simulate success
            }

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(AppConstants.Email.FromName, fromAddress));
            message.To.Add(new MailboxAddress("", email));
            message.Subject = AppConstants.Email.SubjectPasswordReset;

            var resetUrl = $"{_configuration["App:BaseUrl"]}/Account/ResetPassword?token={Uri.EscapeDataString(resetToken)}&email={Uri.EscapeDataString(email)}";

            var bodyBuilder = new BodyBuilder
            {
                HtmlBody = $@"
                    <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
                        <h2 style='color: #333;'>Password Reset Request</h2>
                        <p>You requested to reset your password. Click the button below to reset it:</p>
                        <div style='text-align: center; margin: 30px 0;'>
                            <a href='{resetUrl}' style='background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;'>Reset Password</a>
                        </div>
                        <p>Or copy and paste this link into your browser:</p>
                        <p style='word-break: break-all; color: #666;'>{resetUrl}</p>
                        <p>This link will expire in {AppConstants.PasswordResetTokenExpiryMinutes} minutes.</p>
                        <p>If you didn't request this reset, please ignore this email.</p>
                    </div>"
            };

            message.Body = bodyBuilder.ToMessageBody();

            using var client = new SmtpClient();
            await client.ConnectAsync(smtpHost, int.Parse(smtpPort!), false);
            await client.AuthenticateAsync(smtpUser, smtpPass);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);

            _logger.LogInformation("Password reset email sent successfully to {Email}", email);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send password reset email to {Email}", email);
            
            // In development mode, simulate success even if SMTP fails
            var env = _configuration["ASPNETCORE_ENVIRONMENT"] ?? Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Development";
            if (string.Equals(env, "Development", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("SMTP email send failed but continuing because environment is Development. Reset token: {Token}", resetToken);
                return true; // simulate success in development
            }
            
            return false;
        }
    }

    public async Task<bool> SendWelcomeEmailAsync(string email, string firstName)
    {
        try
        {
            // If SMTP is not configured, simulate success for development/testing
            var smtpHost = _configuration["Email:SmtpHost"]; 
            var smtpPort = _configuration["Email:SmtpPort"]; 
            var smtpUser = _configuration["Email:Username"]; 
            var smtpPass = _configuration["Email:Password"]; 
            var fromAddress = _configuration["Email:FromAddress"]; 

            if (string.IsNullOrWhiteSpace(smtpHost) || string.IsNullOrWhiteSpace(smtpPort) ||
                string.IsNullOrWhiteSpace(smtpUser) || string.IsNullOrWhiteSpace(smtpPass) ||
                string.IsNullOrWhiteSpace(fromAddress))
            {
                _logger.LogWarning("SMTP not configured. Simulating welcome email delivery to {Email}.", email);
                return true; // simulate success
            }

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(AppConstants.Email.FromName, fromAddress));
            message.To.Add(new MailboxAddress(firstName, email));
            message.Subject = AppConstants.Email.SubjectWelcome;

            var setup2FaUrl = $"{_configuration["App:BaseUrl"]}/Account/Setup2fa";

            var bodyBuilder = new BodyBuilder
            {
                HtmlBody = $@"
                    <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
                        <h2 style='color: #333;'>Welcome to TurbineAero</h2>
                        <p>Hi {firstName},</p>
                        <p>Your TurbineAero account has been successfully created.</p>
                        <p><strong>Next Step:</strong> Please set up your Two-Factor Authentication (2FA) to secure your account.</p>
                        <div style='text-align: center; margin: 30px 0;'>
                            <a href='{setup2FaUrl}' style='background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;'>Set Up 2FA</a>
                        </div>
                        <p>Click the link above or go to: <a href='{setup2FaUrl}'>{setup2FaUrl}</a></p>
                        <p>Thank you,<br>The TurbineAero Team</p>
                    </div>"
            };

            message.Body = bodyBuilder.ToMessageBody();

            using var client = new SmtpClient();
            await client.ConnectAsync(smtpHost, int.Parse(smtpPort!), false);
            await client.AuthenticateAsync(smtpUser, smtpPass);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);

            _logger.LogInformation("Welcome email sent successfully to {Email}", email);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send welcome email to {Email}", email);
            return false;
        }
    }
}
