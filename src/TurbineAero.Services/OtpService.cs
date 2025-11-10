using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;
using TurbineAero.Core.Constants;
using TurbineAero.Core.Interfaces;
using TurbineAero.Data;
using TurbineAero.Data.Models;

namespace TurbineAero.Services;

public class OtpService : IOtpService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<OtpService> _logger;

    public OtpService(ApplicationDbContext context, ILogger<OtpService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<string> GenerateOtpAsync(string identifier, OtpType type)
    {
        // Generate cryptographically secure 6-digit OTP
        var otp = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");

        // Hash the OTP
        var otpHash = HashOtp(otp);

        // Clean up any existing OTPs for this identifier and type
        var existingOtps = await _context.OtpLogs
            .Where(o => o.Identifier == identifier && o.OtpType == type.ToString())
            .ToListAsync();

        _context.OtpLogs.RemoveRange(existingOtps);

        // Create new OTP log
        var otpLog = new OtpLog
        {
            Identifier = identifier,
            OtpHash = otpHash,
            OtpType = type.ToString(),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(AppConstants.OtpExpiryMinutes),
            IsUsed = false,
            AttemptCount = 0
        };

        _context.OtpLogs.Add(otpLog);
        await _context.SaveChangesAsync();

        _logger.LogInformation("OTP generated for {Identifier} ({Type})", identifier, type);
        return otp;
    }

    public async Task<bool> VerifyOtpAsync(string identifier, string otp, OtpType type)
    {
        try
        {
            var otpLog = await _context.OtpLogs
                .Where(o => o.Identifier == identifier && 
                           o.OtpType == type.ToString() && 
                           !o.IsUsed && 
                           o.ExpiresAt > DateTime.UtcNow)
                .OrderByDescending(o => o.CreatedAt)
                .FirstOrDefaultAsync();

            if (otpLog == null)
            {
                _logger.LogWarning("No valid OTP found for {Identifier} ({Type})", identifier, type);
                return false;
            }

            // Check attempt count
            if (otpLog.AttemptCount >= AppConstants.MaxOtpAttempts)
            {
                _logger.LogWarning("Max OTP attempts exceeded for {Identifier} ({Type})", identifier, type);
                return false;
            }

            // Verify OTP
            var otpHash = HashOtp(otp);
            if (otpLog.OtpHash != otpHash)
            {
                otpLog.AttemptCount++;
                await _context.SaveChangesAsync();
                _logger.LogWarning("Invalid OTP attempt for {Identifier} ({Type})", identifier, type);
                return false;
            }

            // Mark as used
            otpLog.IsUsed = true;
            await _context.SaveChangesAsync();

            _logger.LogInformation("OTP verified successfully for {Identifier} ({Type})", identifier, type);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error verifying OTP for {Identifier} ({Type})", identifier, type);
            return false;
        }
    }

    public async Task<bool> IsOtpValidAsync(string identifier, OtpType type)
    {
        var otpLog = await _context.OtpLogs
            .Where(o => o.Identifier == identifier && 
                       o.OtpType == type.ToString() && 
                       !o.IsUsed && 
                       o.ExpiresAt > DateTime.UtcNow)
            .OrderByDescending(o => o.CreatedAt)
            .FirstOrDefaultAsync();

        return otpLog != null;
    }

    public async Task CleanupExpiredOtpsAsync()
    {
        var expiredOtps = await _context.OtpLogs
            .Where(o => o.ExpiresAt < DateTime.UtcNow)
            .ToListAsync();

        if (expiredOtps.Any())
        {
            _context.OtpLogs.RemoveRange(expiredOtps);
            await _context.SaveChangesAsync();
            _logger.LogInformation("Cleaned up {Count} expired OTPs", expiredOtps.Count);
        }
    }

    private static string HashOtp(string otp)
    {
        using var sha256 = SHA256.Create();
        var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(otp));
        return Convert.ToBase64String(hashedBytes);
    }
}
