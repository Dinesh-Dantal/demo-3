using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PenToPublic.Models;

[Table("Review")]
public partial class Review
{
    [Key]
    public int ReviewId { get; set; }

    [ForeignKey("User")]
    public int? UserId { get; set; }

    [ForeignKey("Book")]
    public int? BookId { get; set; }

    public int? Rating { get; set; }

    public string? Comment { get; set; }

    public DateTime? ReviewedAt { get; set; }

    public virtual Book? Book { get; set; }

    public virtual User? User { get; set; }
}
