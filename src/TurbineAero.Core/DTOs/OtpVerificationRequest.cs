using System.ComponentModel.DataAnnotations;

namespace TurbineAero.Core.DTOs;

public class OtpVerificationRequest
{
    [Required]
    public string Email { get; set; } = string.Empty;

    [Required]
    [StringLength(6, MinimumLength = 6)]
    public string EmailOtp { get; set; } = string.Empty;

    [Required]
    [StringLength(6, MinimumLength = 6)]
    public string PhoneOtp { get; set; } = string.Empty;
}
