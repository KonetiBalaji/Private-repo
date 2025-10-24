namespace TurbineAero.Core.Interfaces;

public interface IEmailService
{
    Task<bool> SendOtpEmailAsync(string email, string otp);
    Task<bool> SendPasswordResetEmailAsync(string email, string resetToken);
    Task<bool> SendWelcomeEmailAsync(string email, string firstName);
}
