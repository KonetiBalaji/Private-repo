using System.ComponentModel.DataAnnotations;

namespace TurbineAero.Core.DTOs;

public class ResendOtpRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
}
