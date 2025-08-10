using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PenToPublic.Models
{
    [Table("OtpEntry")]
    public class OtpEntry
    {
        [Key]
        public int OtpId { get; set; }

        [Required]
        public string Email { get; set; } = null!;

        [Required]
        public string Otp { get; set; } = null!;

        public DateTime ExpiryTime { get; set; }
    }
}
