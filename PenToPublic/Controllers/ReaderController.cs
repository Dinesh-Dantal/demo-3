using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PenToPublic.Data;
using PenToPublic.DTOs;
using PenToPublic.Models;

namespace PenToPublic.Controllers
{
    [Route("api/Reader")]
    [ApiController]
    public class ReaderController : ControllerBase
    {
        private readonly PenToPublicContext _context;

        public ReaderController(PenToPublicContext context)
        {
            _context = context;
        }

        // GET: api/Reader/{userId}/subscription
        [HttpGet("{userId}/subscription")]
        public async Task<IActionResult> GetSubscription(int userId)
        {
            var payment = await _context.Payments
                .Where(p => p.UserId == userId && p.Status == "Success")
                .OrderByDescending(p => p.PaymentDate)
                .FirstOrDefaultAsync();

            if (payment == null || payment.EndDate == null || payment.EndDate < DateTime.UtcNow)
            {
                return Ok(new { isSubscribed = false });
            }

            return Ok(new
            {
                isSubscribed = true,
                endDate = payment.EndDate.Value.ToString("yyyy-MM-dd"),
                paymentMode = payment.PaymentMode,
                status = payment.Status
            });
        }

        // POST: api/Reader/{userId}/subscribe (Razorpay payment)
        [HttpPost("{userId}/subscribe")]
        public async Task<IActionResult> Subscribe(int userId, [FromBody] PaymentDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var payment = new Payment
            {
                UserId = userId,
                Amount = dto.Amount,
                PaymentDate = DateTime.UtcNow,
                EndDate = DateTime.UtcNow.AddMonths(1),
                PaymentMode = dto.PaymentMode,
                Status = "Success",
                RazorpayOrderId = dto.RazorpayOrderId,
                RazorpayPaymentId = dto.RazorpayPaymentId,
                RazorpaySignature = dto.RazorpaySignature
            };

            _context.Payments.Add(payment);
            await _context.SaveChangesAsync();

            return Ok(new { message = "Subscription successful" });
        }

        // PUT: api/Reader/{userId}/subscribe/manual (Manual test)
        [HttpPut("{userId}/subscribe/manual")]
        public async Task<IActionResult> ManualSubscribe(int userId, [FromBody] dynamic data)
        {
            string plan = data.plan;
            var now = DateTime.UtcNow;
            var endDate = plan == "yearly" ? now.AddYears(1) : now.AddMonths(1);
            var amount = plan == "yearly" ? 999 : 199;

            var payment = new Payment
            {
                UserId = userId,
                Amount = amount,
                PaymentDate = now,
                EndDate = endDate,
                PaymentMode = "Manual",
                Status = "Success",
                RazorpayOrderId = Guid.NewGuid().ToString()
            };

            _context.Payments.Add(payment);
            await _context.SaveChangesAsync();

            return Ok(new { message = $"Subscribed manually to {plan} plan" });
        }
    }
}
