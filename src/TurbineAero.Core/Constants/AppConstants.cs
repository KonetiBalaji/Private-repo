namespace TurbineAero.Core.Constants;

public static class AppConstants
{
    public const int OtpLength = 6;
    public const int OtpExpiryMinutes = 5;
    public const int OtpResendCooldownSeconds = 60;
    public const int PasswordResetTokenExpiryMinutes = 15;
    public const int MaxOtpAttempts = 3;
    
    public static class Jwt
    {
        public const int AccessTokenExpiryMinutes = 60;
        public const int RefreshTokenExpiryDays = 30;
    }
    
    public static class Email
    {
        public const string FromName = "TurbineAero";
        public const string SubjectOtp = "Your Verification Code";
        public const string SubjectPasswordReset = "Password Reset Request";
        public const string SubjectWelcome = "Welcome to TurbineAero";
    }
    
    public static class Sms
    {
        public const string FromNumber = "+1234567890";
    }
}
