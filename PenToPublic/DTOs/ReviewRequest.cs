namespace PenToPublic.DTOs
{
    public class ReviewRequest
    {
        public int UserId { get; set; }
        public int Rating { get; set; }
        public string? Comment { get; set; }
    }
}
