namespace PenToPublic.DTOs
{
    public class BookWithApprovalDto
    {
        public int BookId { get; set; }
        public string Title { get; set; }
        public string? Description { get; set; }
        public bool? IsFree { get; set; }
        public string? Status { get; set; }
        public DateTime? UploadDate { get; set; }
        public string? AdminDecision { get; set; }
        public DateTime? DecisionDate { get; set; }
    }
}
