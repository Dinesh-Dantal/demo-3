using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PenToPublic.Data;
using PenToPublic.Models;

namespace PenToPublic.Controllers
{
    [ApiController]
    [Route("api/upload")]
    public class UploadController : ControllerBase
    {
        private readonly PenToPublicContext _context;

        public UploadController(PenToPublicContext context)
        {
            _context = context;
        }

        public class UploadBookDto
        {
            public int AuthorId { get; set; }
            public string Title { get; set; } = null!;
            public string Description { get; set; } = null!;
            public bool IsFree { get; set; }
            public bool IsAudioBook { get; set; }
            public string PdfPath { get; set; } = null!;
            public string FrontPageLink { get; set; } = null!;
            public string? AudioPath { get; set; } // Optional
            public List<int> CategoryIds { get; set; } = new(); // List of selected category IDs
        }

        [HttpPost]
        public async Task<IActionResult> UploadBook([FromBody] UploadBookDto dto)
        {
            if (string.IsNullOrWhiteSpace(dto.Title) || string.IsNullOrWhiteSpace(dto.PdfPath) || string.IsNullOrWhiteSpace(dto.FrontPageLink))
                return BadRequest("Missing required fields.");

            // ✅ Check if author (user) exists
            var authorExists = await _context.Users.AnyAsync(u => u.UserId == dto.AuthorId);
            if (!authorExists)
                return BadRequest("Invalid AuthorId. User not found.");

            // ✅ Create Book
            var newBook = new Book
            {
                AuthorId = dto.AuthorId,
                Title = dto.Title,
                Description = dto.Description,
                IsFree = dto.IsFree,
                Status = "pending",
                UploadDate = DateTime.Now,
            };

            _context.Books.Add(newBook);
            await _context.SaveChangesAsync(); // Save to get BookId

            // ✅ Add Categories
            foreach (var categoryId in dto.CategoryIds)
            {
                // Check if category exists (optional)
                if (await _context.Categories.AnyAsync(c => c.CategoryId == categoryId))
                {
                    var bookCategory = new BookCategory
                    {
                        BookId = newBook.BookId,
                        CategoryId = categoryId
                    };
                    _context.BookCategories.Add(bookCategory);
                }
            }

            // ✅ Add BookFile
            var bookFile = new BookFile
            {
                BookId = newBook.BookId,
                PdfPath = dto.PdfPath,
                AudioPath = dto.AudioPath,
                FrontPageLink = dto.FrontPageLink
            };
            _context.BookFiles.Add(bookFile);

            await _context.SaveChangesAsync();

            return Ok(new { message = "Book uploaded successfully", bookId = newBook.BookId });
        }
    }
}
