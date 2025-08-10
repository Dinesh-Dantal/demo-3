using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PenToPublic.Models;

[Table("Admin")]
public partial class Admin
{
    [Key]
    public int AdminId { get; set; }

    [Required]
    public string Email { get; set; } = null!;

    [Required]
    public string UserName { get; set; } = null!;

    [Required]
    public string Password { get; set; } = null!;

    public virtual ICollection<AdminApproval> AdminApprovals { get; set; } = new List<AdminApproval>();
}
