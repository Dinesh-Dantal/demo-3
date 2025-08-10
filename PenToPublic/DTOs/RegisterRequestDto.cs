namespace PenToPublic.DTOs
{
    public class RegisterRequestDto
    {
        public string Email { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }

        // Reader-specific
        public bool? IsSubscribed { get; set; }

        // Author-specific
        public string? Bio { get; set; }
    }
}
