using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;
using System.Threading.Tasks;

namespace PenToPublic.Services
{
    public class EmailService
    {
        private readonly IConfiguration _config;

        public EmailService(IConfiguration config)
        {
            _config = config;
        }

        public async Task SendOtpEmailAsync(string toEmail, string otp)
        {
            try
            {
                var smtpClient = new SmtpClient(_config["SmtpSettings:Host"])
                {
                    Port = int.Parse(_config["SmtpSettings:Port"] ?? "587"),
                    Credentials = new NetworkCredential(
                        _config["SmtpSettings:Username"],
                        _config["SmtpSettings:Password"]
                    ),
                    EnableSsl = true
                };

                var message = new MailMessage
                {
                    From = new MailAddress(
                        _config["SmtpSettings:SenderEmail"],
                        _config["SmtpSettings:SenderName"]
                    ),
                    Subject = "Your OTP for Password Reset",
                    Body = $"Your OTP is: {otp}",
                    IsBodyHtml = false
                };

                message.To.Add(toEmail);

                await smtpClient.SendMailAsync(message);
            }
            catch (Exception ex)
            {
                // You can log the exception or rethrow with more context
                throw new Exception($"Failed to send OTP email: {ex.Message}", ex);
            }
        }
    }
}
