using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PenToPublic.Models;

[Table("BookCategory")]
public partial class BookCategory
{
    [Key]
    public int Id { get; set; }

    [ForeignKey("Book")]
    public int BookId { get; set; }

    [ForeignKey("Category")]
    public int CategoryId { get; set; }

    public virtual Book Book { get; set; } = null!;

    public virtual Category Category { get; set; } = null!;
}
