using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PenToPublic.Data;
using PenToPublic.Models;
using PenToPublic.DTOs;
using Razorpay.Api;
using AutoMapper;
using Payment = PenToPublic.Models.Payment;

namespace PenToPublic.Controllers
{
    [ApiController]
    [Route("api/payment")]
    public class PaymentController : ControllerBase
    {
        private readonly RazorpayService _razorpayService;
        private readonly PenToPublicContext _context;
        private readonly IMapper _mapper;

        public PaymentController(IMapper mapper, RazorpayService razorpayService, PenToPublicContext context)
        {
            _mapper = mapper;
            _razorpayService = razorpayService;
            _context = context;
        }

        // ✅ 1. Create Razorpay Order (Fix: Accept JSON not raw decimal)
        [HttpPost("create-order")]
        public IActionResult CreateOrder([FromBody] CreateOrderDto dto)
        {
            if (dto.Amount <= 0)
                return BadRequest("Amount must be greater than 0");

            var order = _razorpayService.CreateOrder(dto.Amount);
            return Ok(new
            {
                orderId = order["id"].ToString(),
                amount = order["amount"],
                currency = order["currency"]
            });
        }

        // ✅ 2. Confirm Payment (After Razorpay success)
        [HttpPost("confirm")]
        public async Task<IActionResult> ConfirmPayment([FromBody] PaymentCreateDto dto)
        {
            if (dto.UserId == 0 || dto.Amount <= 0)
                return BadRequest("Invalid payment data.");

            var user = await _context.Users
                .Include(u => u.Reg)
                .FirstOrDefaultAsync(u => u.UserId == dto.UserId);

            if (user == null)
                return NotFound("User not found.");

            var payment = new Payment
            {
                UserId = dto.UserId,
                Amount = dto.Amount,
                PaymentDate = DateTime.Now,
                EndDate = dto.EndDate,
                PaymentMode = dto.PaymentMode,
                Status = "Success"
            };

            _context.Payments.Add(payment);
            await _context.SaveChangesAsync();

            var response = new PaymentResponseDto
            {
                PaymentId = payment.PaymentId,
                Amount = payment.Amount ?? 0,
                PaymentMode = payment.PaymentMode,
                Status = payment.Status,
                PaymentDate = payment.PaymentDate ?? DateTime.MinValue,
                EndDate = payment.EndDate ?? DateTime.MinValue,
                UserName = user.Reg?.UserName ?? "Unknown"
            };

            return Ok(response);
        }

        // ✅ 3. Get All Payments
        [HttpGet("all")]
        public async Task<IActionResult> GetAllPayments()
        {
            var payments = await _context.Payments
                .Include(p => p.User)
                .ThenInclude(u => u.Reg)
                .ToListAsync();

            var dtoList = payments.Select(p => new PaymentResponseDto
            {
                PaymentId = p.PaymentId,
                Amount = p.Amount ?? 0,
                PaymentMode = p.PaymentMode,
                Status = p.Status,
                PaymentDate = p.PaymentDate ?? DateTime.MinValue,
                EndDate = p.EndDate ?? DateTime.MinValue,
                UserName = p.User?.Reg?.UserName ?? "Unknown"
            }).ToList();

            return Ok(dtoList);
        }

        // ✅ 4. Manual Subscribe with Plan Type (monthly or yearly)
        [HttpPost("subscribe")]
        public async Task<IActionResult> Subscribe([FromBody] PaymentRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.SubscriptionType) ||
                !(request.SubscriptionType.ToLower() == "monthly" || request.SubscriptionType.ToLower() == "yearly"))
            {
                return BadRequest(new { message = "Invalid subscription type. Use 'monthly' or 'yearly'." });
            }

            var user = await _context.Users
                .Include(u => u.ReaderDetail)
                .FirstOrDefaultAsync(u => u.UserId == request.UserId);

            if (user == null)
                return NotFound(new { message = "User not found." });

            decimal amount = request.SubscriptionType.ToLower() == "monthly" ? 200 : 900;
            DateTime endDate = request.SubscriptionType.ToLower() == "monthly"
                ? DateTime.Now.AddMonths(1)
                : DateTime.Now.AddYears(1);

            var payment = new Payment
            {
                UserId = user.UserId,
                Amount = amount,
                PaymentDate = DateTime.Now,
                EndDate = endDate,
                PaymentMode = "Manual",
                Status = "Success"
            };

            _context.Payments.Add(payment);

            if (user.ReaderDetail != null)
            {
                user.ReaderDetail.IsSubscribed = true;
            }
            else
            {
                user.ReaderDetail = new ReaderDetail
                {
                    UserId = user.UserId,
                    IsSubscribed = true
                };
                _context.ReaderDetails.Add(user.ReaderDetail);
            }

            await _context.SaveChangesAsync();

            return Ok(new
            {
                message = $"Subscribed successfully for {request.SubscriptionType} plan.",
                amountPaid = amount,
                userId = user.UserId,
                subscriptionStatus = true
            });
        }
    }
}
