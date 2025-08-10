using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PenToPublic.Models;

[Table("AuthorDetail")]
public partial class AuthorDetail
{
    [Key]
    public int AuthorId { get; set; }

    [ForeignKey("User")]
    public int? UserId { get; set; }

    public string? Bio { get; set; }

    public virtual User? User { get; set; }
}
