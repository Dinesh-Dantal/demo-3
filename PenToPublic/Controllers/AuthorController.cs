using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PenToPublic.Data;
using PenToPublic.DTOs;
using PenToPublic.DTOs;
using PenToPublic.Models;

namespace PenToPublic.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthorController : ControllerBase
{
    private readonly PenToPublicContext _context;

    public AuthorController(PenToPublicContext context)
    {
        _context = context;
    }

    // GET: api/author/books/{userId}
    [HttpGet("books/{userId}")]
    public async Task<ActionResult<IEnumerable<BookWithApprovalDto>>> GetAuthorBooks(int userId)
    {
        var books = await _context.Books
            .Where(b => b.AuthorId == userId)
            .Include(b => b.AdminApprovals)
            .Select(b => new BookWithApprovalDto
            {
                BookId = b.BookId,
                Title = b.Title,
                Description = b.Description,
                IsFree = b.IsFree,
                Status = b.Status,
                UploadDate = b.UploadDate,
                AdminDecision = b.AdminApprovals.OrderByDescending(a => a.DecisionDate).FirstOrDefault().Decision,
                DecisionDate = b.AdminApprovals.OrderByDescending(a => a.DecisionDate).FirstOrDefault().DecisionDate
            })
            .ToListAsync();

        return Ok(books);
    }

    // POST: api/author/upload
    [HttpPost("upload")]
    public async Task<IActionResult> UploadBook([FromBody] Book book)
    {
        book.UploadDate = DateTime.UtcNow;
        _context.Books.Add(book);
        await _context.SaveChangesAsync();
        return Ok(book);
    }
}
