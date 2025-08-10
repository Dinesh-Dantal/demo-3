using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PenToPublic.Models;

[Table("ReaderDetail")]
public partial class ReaderDetail
{
    [Key]
    public int ReaderId { get; set; }

    [ForeignKey("User")]
    public int? UserId { get; set; }

    public bool? IsSubscribed { get; set; }

    public virtual User? User { get; set; }
}
