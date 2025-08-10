namespace PenToPublic.Models
{
    public class SmtpSettings
    {
        public string Host { get; set; } = null!;
        public int Port { get; set; }
        public string SenderEmail { get; set; } = null!;
        public string SenderName { get; set; } = null!;
        public string Username { get; set; } = null!;
        public string Password { get; set; } = null!;
    }
}
