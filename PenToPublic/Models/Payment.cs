using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PenToPublic.Models
{
    [Table("Payment")]
    public class Payment
    {
        [Key]
        public int PaymentId { get; set; }

        [ForeignKey("User")]
        public int? UserId { get; set; }

        public decimal? Amount { get; set; }

        public DateTime? PaymentDate { get; set; }

        public DateTime? EndDate { get; set; }  // ✅ Use DateTime here

        public string? PaymentMode { get; set; }

        public string? Status { get; set; }

        public string? RazorpayOrderId { get; set; }

        public string? RazorpayPaymentId { get; set; }

        public string? RazorpaySignature { get; set; }

        public virtual User? User { get; set; }
    }
}
