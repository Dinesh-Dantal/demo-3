using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PenToPublic.Models;

[Table("Category")]
public partial class Category
{
    [Key]
    public int CategoryId { get; set; }

    [Required]
    public string Name { get; set; } = null!;

    public virtual ICollection<BookCategory> BookCategories { get; set; } = new List<BookCategory>();
}
