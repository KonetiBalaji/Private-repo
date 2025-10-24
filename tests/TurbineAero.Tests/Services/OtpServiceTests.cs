using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using TurbineAero.Core.Interfaces;
using TurbineAero.Data;
using TurbineAero.Services;
using Xunit;

namespace TurbineAero.Tests.Services;

public class OtpServiceTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly IOtpService _otpService;

    public OtpServiceTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);
        _context.Database.EnsureCreated();

        var logger = new MockLogger<OtpService>();
        _otpService = new OtpService(_context, logger);
    }

    [Fact]
    public async Task GenerateOtpAsync_ShouldCreateOtpLog()
    {
        // Arrange
        var identifier = "test@example.com";
        var type = OtpType.Email;

        // Act
        var otp = await _otpService.GenerateOtpAsync(identifier, type);

        // Assert
        Assert.NotNull(otp);
        Assert.Equal(6, otp.Length);
        Assert.True(int.TryParse(otp, out _));

        var otpLog = await _context.OtpLogs
            .FirstOrDefaultAsync(o => o.Identifier == identifier && o.OtpType == type.ToString());
        
        Assert.NotNull(otpLog);
        Assert.Equal(identifier, otpLog.Identifier);
        Assert.Equal(type.ToString(), otpLog.OtpType);
        Assert.False(otpLog.IsUsed);
        Assert.Equal(0, otpLog.AttemptCount);
    }

    [Fact]
    public async Task VerifyOtpAsync_WithValidOtp_ShouldReturnTrue()
    {
        // Arrange
        var identifier = "test@example.com";
        var type = OtpType.Email;
        var otp = await _otpService.GenerateOtpAsync(identifier, type);

        // Act
        var result = await _otpService.VerifyOtpAsync(identifier, otp, type);

        // Assert
        Assert.True(result);

        var otpLog = await _context.OtpLogs
            .FirstOrDefaultAsync(o => o.Identifier == identifier && o.OtpType == type.ToString());
        
        Assert.NotNull(otpLog);
        Assert.True(otpLog.IsUsed);
    }

    [Fact]
    public async Task VerifyOtpAsync_WithInvalidOtp_ShouldReturnFalse()
    {
        // Arrange
        var identifier = "test@example.com";
        var type = OtpType.Email;
        await _otpService.GenerateOtpAsync(identifier, type);

        // Act
        var result = await _otpService.VerifyOtpAsync(identifier, "123456", type);

        // Assert
        Assert.False(result);

        var otpLog = await _context.OtpLogs
            .FirstOrDefaultAsync(o => o.Identifier == identifier && o.OtpType == type.ToString());
        
        Assert.NotNull(otpLog);
        Assert.False(otpLog.IsUsed);
        Assert.Equal(1, otpLog.AttemptCount);
    }

    [Fact]
    public async Task VerifyOtpAsync_WithExpiredOtp_ShouldReturnFalse()
    {
        // Arrange
        var identifier = "test@example.com";
        var type = OtpType.Email;
        var otp = await _otpService.GenerateOtpAsync(identifier, type);

        // Manually expire the OTP
        var otpLog = await _context.OtpLogs
            .FirstOrDefaultAsync(o => o.Identifier == identifier && o.OtpType == type.ToString());
        if (otpLog != null)
        {
            otpLog.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
            await _context.SaveChangesAsync();
        }

        // Act
        var result = await _otpService.VerifyOtpAsync(identifier, otp, type);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task IsOtpValidAsync_WithValidOtp_ShouldReturnTrue()
    {
        // Arrange
        var identifier = "test@example.com";
        var type = OtpType.Email;
        await _otpService.GenerateOtpAsync(identifier, type);

        // Act
        var result = await _otpService.IsOtpValidAsync(identifier, type);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task IsOtpValidAsync_WithNoOtp_ShouldReturnFalse()
    {
        // Arrange
        var identifier = "test@example.com";
        var type = OtpType.Email;

        // Act
        var result = await _otpService.IsOtpValidAsync(identifier, type);

        // Assert
        Assert.False(result);
    }

    public void Dispose()
    {
        _context.Dispose();
    }
}

// Mock logger implementation
public class MockLogger<T> : ILogger<T>
{
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        // Mock implementation - does nothing
    }
}
