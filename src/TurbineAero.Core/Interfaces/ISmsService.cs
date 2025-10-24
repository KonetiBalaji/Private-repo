namespace TurbineAero.Core.Interfaces;

public interface ISmsService
{
    Task<bool> SendOtpSmsAsync(string phoneNumber, string otp);
}
