namespace PenToPublic.DTOs
{
    public class ReadingProgressRequest
    {
        public int LastPage { get; set; }
        public double PercentRead { get; set; }
        public int TotalPages { get; set; }
    }
}
