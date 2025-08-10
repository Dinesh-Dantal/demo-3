using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PenToPublic.Data;
using PenToPublic.DTOs;
using PenToPublic.DTOs;
using PenToPublic.Models;
using PenToPublic.Services;

namespace PenToPublic.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ForgotPasswordController : ControllerBase
    {
        private readonly PenToPublicContext _context;
        private readonly EmailService _emailService;

        public ForgotPasswordController(PenToPublicContext context, EmailService emailService)
        {
            _context = context;
            _emailService = emailService;
        }

        [HttpPost("send-otp")]
        public async Task<IActionResult> SendOtp([FromBody] SendOtpRequest request)
        {
            var reg = await _context.Registrations.FirstOrDefaultAsync(r => r.Email == request.Email);
            if (reg == null) return NotFound("Email not registered.");

            var otp = new Random().Next(100000, 999999).ToString();
            var expiry = DateTime.UtcNow.AddMinutes(10);

            var existingOtp = await _context.OtpEntries.FirstOrDefaultAsync(o => o.Email == request.Email);
            if (existingOtp != null)
            {
                existingOtp.Otp = otp;
                existingOtp.ExpiryTime = expiry;
            }
            else
            {
                await _context.OtpEntries.AddAsync(new OtpEntry
                {
                    Email = request.Email,
                    Otp = otp,
                    ExpiryTime = expiry
                });
            }

            await _context.SaveChangesAsync();
            await _emailService.SendOtpEmailAsync(request.Email, otp);

            return Ok("OTP sent to your email.");
        }

        [HttpPost("verify-otp")]
        public async Task<IActionResult> VerifyOtp([FromBody] VerifyOtpRequest request)
        {
            var entry = await _context.OtpEntries.FirstOrDefaultAsync(o => o.Email == request.Email);
            if (entry == null || entry.Otp != request.Otp || entry.ExpiryTime < DateTime.UtcNow)
                return BadRequest("Invalid or expired OTP.");

            return Ok("OTP verified.");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            var reg = await _context.Registrations.FirstOrDefaultAsync(r => r.Email == request.Email);
            if (reg == null) return NotFound("User not found.");

            reg.Password = request.NewPassword;
            await _context.SaveChangesAsync();

            return Ok("Password has been reset.");
        }
    }
}
