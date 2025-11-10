using System.ComponentModel.DataAnnotations;

namespace TurbineAero.Core.DTOs;

public class VerifyTwoFactorRequest
{
    [Required]
    [StringLength(6, MinimumLength = 6)]
    public string Code { get; set; } = string.Empty;
}
