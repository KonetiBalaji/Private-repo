using System.ComponentModel.DataAnnotations;

namespace TurbineAero.Core.DTOs;

public class Login2FASendOtpRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
}

