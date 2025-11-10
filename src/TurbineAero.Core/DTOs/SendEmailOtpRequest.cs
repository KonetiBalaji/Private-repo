using System.ComponentModel.DataAnnotations;

namespace TurbineAero.Core.DTOs;

public class SendEmailOtpRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
}

