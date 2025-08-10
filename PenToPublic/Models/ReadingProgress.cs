using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PenToPublic.Models;

[Table("ReadingProgress")]
public partial class ReadingProgress
{
    [Key]
    public int ProgressId { get; set; }

    [ForeignKey("User")]
    public int? UserId { get; set; }

    [ForeignKey("Book")]
    public int? BookId { get; set; }

    public decimal? PercentRead { get; set; }

    public int? LastPage { get; set; }

    public int TotalPages { get; set; }  

    public DateTime? UpdatedAt { get; set; }

    public virtual Book? Book { get; set; }

    public virtual User? User { get; set; }
}
