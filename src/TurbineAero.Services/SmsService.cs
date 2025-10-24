using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using TurbineAero.Core.Constants;
using TurbineAero.Core.Interfaces;
using Twilio;
using Twilio.Rest.Api.V2010.Account;

namespace TurbineAero.Services;

public class SmsService : ISmsService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<SmsService> _logger;

    public SmsService(IConfiguration configuration, ILogger<SmsService> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<bool> SendOtpSmsAsync(string phoneNumber, string otp)
    {
        try
        {
            // If Twilio is not configured, simulate success for development/testing
            var accountSid = _configuration["Twilio:AccountSid"]; 
            var authToken = _configuration["Twilio:AuthToken"]; 
            var fromNumber = _configuration["Twilio:FromPhoneNumber"]; 

            if (string.IsNullOrWhiteSpace(accountSid) || string.IsNullOrWhiteSpace(authToken) || string.IsNullOrWhiteSpace(fromNumber))
            {
                _logger.LogWarning("Twilio not configured. Simulating OTP SMS to {Phone}. OTP: {Otp}", phoneNumber, otp);
                return true; // simulate success
            }

            TwilioClient.Init(accountSid, authToken);

            var message = await MessageResource.CreateAsync(
                body: $"Your TurbineAero verification code is: {otp}. This code will expire in {AppConstants.OtpExpiryMinutes} minutes.",
                from: new Twilio.Types.PhoneNumber(fromNumber),
                to: new Twilio.Types.PhoneNumber(phoneNumber)
            );

            _logger.LogInformation("OTP SMS sent successfully to {PhoneNumber}. Message SID: {MessageSid}", 
                phoneNumber, message.Sid);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send OTP SMS to {PhoneNumber}", phoneNumber);
            return false;
        }
    }
}
