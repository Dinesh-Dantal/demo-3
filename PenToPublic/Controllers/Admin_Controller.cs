using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PenToPublic.Data;
using PenToPublic.Models;

namespace PenToPublic.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        private readonly PenToPublicContext _context;

        public AdminController(PenToPublicContext context)
        {
            _context = context;
        }

        // 1. Get all pending books with file info and description
        [HttpGet("pending-books")]
        public async Task<IActionResult> GetPendingBooks()
        {
            var books = await _context.Books
                .Where(b => b.Status == "pending")
                .Include(b => b.BookFiles)
                .Select(b => new
                {
                    b.BookId,
                    b.Title,
                    b.Description,
                    b.IsFree,
                    b.UploadDate,
                    Files = b.BookFiles.Select(f => new
                    {
                        f.PdfPath,
                        f.AudioPath,
                        f.FrontPageLink
                    })
                })
                .ToListAsync();

            return Ok(books);
        }

        // 2. Approve a book
        [HttpPost("approve/{bookId}")]
        public async Task<IActionResult> ApproveBook(int bookId, [FromQuery] int adminId)
        {
            var book = await _context.Books.FindAsync(bookId);
            if (book == null) return NotFound();

            book.Status = "approved";
            _context.AdminApprovals.Add(new AdminApproval
            {
                BookId = bookId,
                AdminId = adminId,
                Decision = "approved",
                DecisionDate = DateTime.Now
            });

            await _context.SaveChangesAsync();
            return Ok(new { message = "Book approved" });
        }

        // 3. Reject a book
        [HttpPost("reject/{bookId}")]
        public async Task<IActionResult> RejectBook(int bookId, [FromQuery] int adminId)
        {
            var book = await _context.Books.FindAsync(bookId);
            if (book == null) return NotFound();

            book.Status = "rejected";
            _context.AdminApprovals.Add(new AdminApproval
            {
                BookId = bookId,
                AdminId = adminId,
                Decision = "rejected",
                DecisionDate = DateTime.Now
            });

            await _context.SaveChangesAsync();
            return Ok(new { message = "Book rejected" });
        }

        // 4. Get all readers with subscription status
        [HttpGet("readers")]
        public async Task<IActionResult> GetReaders()
        {
            var readers = await _context.Users
                .Where(u => u.Role == "reader")
                .Include(u => u.Reg)
                .Include(u => u.ReaderDetail)
                .ToListAsync();

            var result = readers.Select(u => new
            {
                u.UserId,
                u.Reg.UserName,
                u.Reg.Email,
                IsSubscribed = u.ReaderDetail?.IsSubscribed ?? false
            });

            return Ok(result);
        }

        // 5. Get all authors and count of approved books
        [HttpGet("authors")]
        public async Task<IActionResult> GetAuthors()
        {
            var authors = await _context.AuthorDetails
                .Include(ad => ad.User)
                .ThenInclude(u => u.Reg)
                .Select(ad => new
                {
                    ad.User.UserId,
                    ad.User.Reg.UserName,
                    ad.User.Reg.Email,
                    BookCount = _context.Books.Count(b => b.AuthorId == ad.AuthorId && b.Status == "approved")
                })
                .ToListAsync();

            return Ok(authors);
        }

        // 6. Get total book count
        [HttpGet("books/summary")]
        public async Task<IActionResult> GetBookCount()
        {
            int totalBooks = await _context.Books.CountAsync();
            return Ok(new { totalBooks });
        }

        // 7. Dashboard summary
        [HttpGet("dashboard")]
        public async Task<IActionResult> GetDashboardData()
        {
            var totalBooks = await _context.Books.CountAsync();
            var approvedBooks = await _context.Books.CountAsync(b => b.Status == "approved");
            var pendingBooks = await _context.Books.CountAsync(b => b.Status == "pending");
            var rejectedBooks = await _context.Books.CountAsync(b => b.Status == "rejected");

            var totalUsers = await _context.Users.ToListAsync();
            var totalAuthors = totalUsers.Count(u => u.Role == "author");
            var totalReaders = totalUsers.Count(u => u.Role == "reader");

            var subscribedReaders = await _context.ReaderDetails.CountAsync(r => r.IsSubscribed == true);

            var result = new
            {
                Books = new
                {
                    Total = totalBooks,
                    Approved = approvedBooks,
                    Pending = pendingBooks,
                    Rejected = rejectedBooks
                },
                Users = new
                {
                    Authors = totalAuthors,
                    Readers = totalReaders,
                    SubscribedReaders = subscribedReaders
                }
            };

            return Ok(result);
        }

        // 8. Get all approval decisions
        [HttpGet("decisions")]
        public async Task<IActionResult> GetApprovalDecisions()
        {
            var decisions = await _context.AdminApprovals
                .Include(d => d.Book)
                .Include(d => d.Admin)
                .Select(d => new
                {
                    d.ApprovalId,
                    BookTitle = d.Book.Title,
                    AdminUserName = d.Admin.UserName,
                    AdminEmail = d.Admin.Email,
                    d.Decision,
                    d.DecisionDate
                })
                .ToListAsync();

            return Ok(decisions);
        }
    }
}
