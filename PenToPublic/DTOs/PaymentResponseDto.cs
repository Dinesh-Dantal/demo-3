namespace PenToPublic.DTOs
{
    public class PaymentResponseDto
    {
        public int PaymentId { get; set; }
        public decimal Amount { get; set; }
        public string PaymentMode { get; set; }
        public string Status { get; set; }
        public DateTime PaymentDate { get; set; }
        public DateTime EndDate { get; set; }
        public string UserName { get; set; }
    }

}
