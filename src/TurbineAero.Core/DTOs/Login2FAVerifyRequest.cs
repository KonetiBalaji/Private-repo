using System.ComponentModel.DataAnnotations;

namespace TurbineAero.Core.DTOs;

public class Login2FAVerifyRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    [StringLength(6, MinimumLength = 6)]
    public string Code { get; set; } = string.Empty;

    [Required]
    public string Method { get; set; } = "authenticator"; // "authenticator" or "email"
}

