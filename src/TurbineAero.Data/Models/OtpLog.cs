using System.ComponentModel.DataAnnotations;

namespace TurbineAero.Data.Models;

public class OtpLog
{
    public int Id { get; set; }
    
    [Required]
    [StringLength(255)]
    public string Identifier { get; set; } = string.Empty;
    
    [Required]
    [StringLength(255)]
    public string OtpHash { get; set; } = string.Empty;
    
    [Required]
    [StringLength(50)]
    public string OtpType { get; set; } = string.Empty;
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public bool IsUsed { get; set; }
    public int AttemptCount { get; set; }
}
