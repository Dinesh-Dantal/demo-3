using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PenToPublic.Data;
using PenToPublic.Models;

namespace PenToPublic.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ReadingProgressController : ControllerBase
    {
        private readonly PenToPublicContext _context;

        public ReadingProgressController(PenToPublicContext context)
        {
            _context = context;
        }

        // 1. Get all reading progress
        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            var result = await _context.ReadingProgresses
                .Include(r => r.Book)
                .Include(r => r.User)
                .Select(p => new
                {
                    p.ProgressId,
                    p.UserId,
                    p.BookId,
                    BookTitle = p.Book != null ? p.Book.Title : null,
                    UserName = p.User != null ? p.User.Reg.UserName : null,
                    p.PercentRead,
                    p.LastPage,
                    p.TotalPages,
                    p.UpdatedAt
                })
                .ToListAsync();

            return Ok(result);
        }

        // 2. Get by progress ID
        [HttpGet("{id}")]
        public async Task<IActionResult> GetById(int id)
        {
            var progress = await _context.ReadingProgresses
                .Include(r => r.Book)
                .Include(r => r.User)
                .Where(r => r.ProgressId == id)
                .Select(p => new
                {
                    p.ProgressId,
                    p.UserId,
                    p.BookId,
                    BookTitle = p.Book != null ? p.Book.Title : null,
                    UserName = p.User != null ? p.User.Reg.UserName : null,
                    p.PercentRead,
                    p.LastPage,
                    p.TotalPages,
                    p.UpdatedAt
                })
                .FirstOrDefaultAsync();

            if (progress == null)
                return NotFound();

            return Ok(progress);
        }

        // 3. Get by user ID
        [HttpGet("user/{userId}")]
        public IActionResult GetByUser(int userId)
        {
            var progress = _context.ReadingProgresses
                .Include(p => p.Book)
                .Where(p => p.UserId == userId)
                .Select(p => new
                {
                    p.ProgressId,
                    p.BookId,
                    BookTitle = p.Book != null ? p.Book.Title : null,
                    p.PercentRead,
                    p.LastPage,
                    p.TotalPages,
                    p.UpdatedAt
                })
                .ToList();

            return Ok(progress);
        }

        // 4. Get by book ID
        [HttpGet("book/{bookId}")]
        public IActionResult GetByBook(int bookId)
        {
            var progress = _context.ReadingProgresses
                .Include(p => p.User)
                .Where(p => p.BookId == bookId)
                .Select(p => new
                {
                    p.ProgressId,
                    p.UserId,
                    UserName = p.User != null ? p.User.Reg.UserName : null,
                    p.PercentRead,
                    p.LastPage,
                    p.TotalPages,
                    p.UpdatedAt
                })
                .ToList();

            return Ok(progress);
        }

        // 5. Get user progress for a specific book
        [HttpGet("user/{userId}/book/{bookId}")]
        public IActionResult GetUserBookProgress(int userId, int bookId)
        {
            var progress = _context.ReadingProgresses
                .Include(p => p.Book)
                .Include(p => p.User)
                .Where(p => p.UserId == userId && p.BookId == bookId)
                .Select(p => new
                {
                    p.ProgressId,
                    p.UserId,
                    p.BookId,
                    BookTitle = p.Book != null ? p.Book.Title : null,
                    UserName = p.User != null ? p.User.Reg.UserName : null,
                    p.PercentRead,
                    p.LastPage,
                    p.TotalPages,
                    p.UpdatedAt
                })
                .FirstOrDefault();

            if (progress == null)
                return NotFound();

            return Ok(progress);
        }

        // 6. Create new reading progress
        [HttpPost]
        public async Task<IActionResult> Create([FromBody] ReadingProgress model)
        {
            model.UpdatedAt = DateTime.UtcNow;
            _context.ReadingProgresses.Add(model);
            await _context.SaveChangesAsync();
            return Ok(model);
        }

        // 7. Update reading progress
        [HttpPut("{id}")]
        public async Task<IActionResult> Update(int id, [FromBody] ReadingProgress model)
        {
            var existing = await _context.ReadingProgresses.FindAsync(id);
            if (existing == null)
                return NotFound();

            existing.PercentRead = model.PercentRead;
            existing.LastPage = model.LastPage;
            existing.TotalPages = model.TotalPages;
            existing.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();
            return Ok(existing);
        }

        // 8. Delete progress
        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete(int id)
        {
            var progress = await _context.ReadingProgresses.FindAsync(id);
            if (progress == null)
                return NotFound();

            _context.ReadingProgresses.Remove(progress);
            await _context.SaveChangesAsync();
            return NoContent();
        }
    }
}
