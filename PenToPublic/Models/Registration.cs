using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PenToPublic.Models;

[Table("Registration")]
public partial class Registration
{
    [Key]
    public int RegId { get; set; }

    [Required]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string UserName { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;

    public virtual User? User { get; set; }
}
