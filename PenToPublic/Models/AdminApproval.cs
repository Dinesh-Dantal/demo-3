using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PenToPublic.Models;

[Table("AdminApproval")]
public partial class AdminApproval
{
    [Key]
    public int ApprovalId { get; set; }

    [ForeignKey("Book")]
    public int? BookId { get; set; }

    [ForeignKey("Admin")]
    public int? AdminId { get; set; }

    public string? Decision { get; set; }

    public DateTime? DecisionDate { get; set; }

    public virtual Admin? Admin { get; set; }

    public virtual Book? Book { get; set; }
}
