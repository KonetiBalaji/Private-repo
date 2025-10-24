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
                _logger.LogWarning("SMTP not configured. Simulating OTP email to {Email}. OTP: {Otp}", email, otp);
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
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(AppConstants.Email.FromName, _configuration["Email:FromAddress"]));
            message.To.Add(new MailboxAddress("", email));
            message.Subject = AppConstants.Email.SubjectPasswordReset;

            var resetUrl = $"{_configuration["App:BaseUrl"]}/reset-password?token={resetToken}&email={email}";

            var bodyBuilder = new BodyBuilder
            {
                HtmlBody = $@"
                    <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
                        <h2 style='color: #333;'>Password Reset Request</h2>
                        <p>You requested to reset your password. Click the button below to reset it:</p>
                        <div style='text-align: center; margin: 30px 0;'>
                            <a href='{resetUrl}' style='background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;'>Reset Password</a>
                        </div>
                        <p>This link will expire in {AppConstants.PasswordResetTokenExpiryMinutes} minutes.</p>
                        <p>If you didn't request this reset, please ignore this email.</p>
                    </div>"
            };

            message.Body = bodyBuilder.ToMessageBody();

            using var client = new SmtpClient();
            await client.ConnectAsync(_configuration["Email:SmtpHost"], 
                int.Parse(_configuration["Email:SmtpPort"]!), false);
            await client.AuthenticateAsync(_configuration["Email:Username"], _configuration["Email:Password"]);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);

            _logger.LogInformation("Password reset email sent successfully to {Email}", email);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send password reset email to {Email}", email);
            return false;
        }
    }

    public async Task<bool> SendWelcomeEmailAsync(string email, string firstName)
    {
        try
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(AppConstants.Email.FromName, _configuration["Email:FromAddress"]));
            message.To.Add(new MailboxAddress(firstName, email));
            message.Subject = AppConstants.Email.SubjectWelcome;

            var bodyBuilder = new BodyBuilder
            {
                HtmlBody = $@"
                    <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
                        <h2 style='color: #333;'>Welcome to TurbineAero, {firstName}!</h2>
                        <p>Your account has been successfully created. You can now log in and start using our services.</p>
                        <div style='text-align: center; margin: 30px 0;'>
                            <a href='{_configuration["App:BaseUrl"]}/login' style='background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;'>Login to Your Account</a>
                        </div>
                        <p>Thank you for choosing TurbineAero!</p>
                    </div>"
            };

            message.Body = bodyBuilder.ToMessageBody();

            using var client = new SmtpClient();
            await client.ConnectAsync(_configuration["Email:SmtpHost"], 
                int.Parse(_configuration["Email:SmtpPort"]!), false);
            await client.AuthenticateAsync(_configuration["Email:Username"], _configuration["Email:Password"]);
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
