// DTOs/PaymentDto.cs
namespace PenToPublic.DTOs
{
    public class PaymentDto
    {
        public int Amount { get; set; }
        public string PaymentMode { get; set; }
        public string RazorpayOrderId { get; set; }
        public string RazorpayPaymentId { get; set; }
        public string RazorpaySignature { get; set; }
    }
}
