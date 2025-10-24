namespace TurbineAero.Core.Interfaces;

public interface IOtpService
{
    Task<string> GenerateOtpAsync(string identifier, OtpType type);
    Task<bool> VerifyOtpAsync(string identifier, string otp, OtpType type);
    Task<bool> IsOtpValidAsync(string identifier, OtpType type);
    Task CleanupExpiredOtpsAsync();
}

public enum OtpType
{
    Email,
    Phone
}
