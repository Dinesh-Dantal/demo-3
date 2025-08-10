using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PenToPublic.Models;

[Table("User")]
public partial class User
{
    [Key]
    public int UserId { get; set; }

    [ForeignKey("Reg")]
    public int? RegId { get; set; }

    [Required]
    public string Role { get; set; } = null!;

    public DateTime? CreatedAt { get; set; }

    public virtual AuthorDetail? AuthorDetail { get; set; }

    public virtual ICollection<Book> Books { get; set; } = new List<Book>();

    public virtual ICollection<Payment> Payments { get; set; } = new List<Payment>();

    public virtual ReaderDetail? ReaderDetail { get; set; }

    public virtual ICollection<ReadingProgress> ReadingProgresses { get; set; } = new List<ReadingProgress>();

    public virtual Registration? Reg { get; set; }

    public virtual ICollection<Review> Reviews { get; set; } = new List<Review>();
}
