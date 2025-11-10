using System.ComponentModel.DataAnnotations;

namespace TurbineAero.Core.DTOs;

public class UpdateUserPreferencesRequest
{
    [Required]
    [RegularExpression("^(light|dark)$", ErrorMessage = "Theme must be 'light' or 'dark'.")]
    public string Theme { get; set; } = "light";
}
