using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PenToPublic.Models;

[Table("BookFile")]
public partial class BookFile
{
    [Key]
    public int FileId { get; set; }

    [ForeignKey("Book")]
    public int? BookId { get; set; }

    [Required]
    public string PdfPath { get; set; } = null!;

    public string? AudioPath { get; set; }

    public string? FrontPageLink { get; set; }

    public virtual Book? Book { get; set; }
}
