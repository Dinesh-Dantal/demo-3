public class PaymentCreateDto
{
    public int UserId { get; set; }
    public decimal Amount { get; set; }
    public DateTime? EndDate { get; set; }
    public string PaymentMode { get; set; }
}
