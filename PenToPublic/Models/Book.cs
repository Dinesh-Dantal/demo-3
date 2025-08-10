using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PenToPublic.Models;

[Table("Book")]
public partial class Book
{
    [Key]
    public int BookId { get; set; }

    [ForeignKey("Author")]
    public int? AuthorId { get; set; }

    [Required]
    public string Title { get; set; } = null!;

    public string? Description { get; set; }

    public bool? IsFree { get; set; }

    public string? Status { get; set; }

    public DateTime? UploadDate { get; set; }

    public bool IsAudible { get; set; }  

    // Navigation properties
    public virtual User? Author { get; set; }

    public virtual ICollection<AdminApproval> AdminApprovals { get; set; } = new List<AdminApproval>();

    public virtual ICollection<BookCategory> BookCategories { get; set; } = new List<BookCategory>();

    public virtual ICollection<BookFile> BookFiles { get; set; } = new List<BookFile>();

    public virtual ICollection<ReadingProgress> ReadingProgresses { get; set; } = new List<ReadingProgress>();

    public virtual ICollection<Review> Reviews { get; set; } = new List<Review>();
}
