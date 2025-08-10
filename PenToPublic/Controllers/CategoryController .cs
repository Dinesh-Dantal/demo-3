using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PenToPublic.Data;
using System.Linq;

namespace PenToPublic.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CategoryController : ControllerBase
    {
        private readonly PenToPublicContext _context;

        public CategoryController(PenToPublicContext context)
        {
            _context = context;
        }

        [HttpGet("books-by-category/{categoryName}")]
        public IActionResult GetBooksByCategory(string categoryName)
        {
            var books = _context.Books
                .Include(b => b.BookCategories)
                    .ThenInclude(bc => bc.Category)
                .Include(b => b.Author)
                    .ThenInclude(u => u.Reg)
                .Include(b => b.BookFiles)
                .Where(b => b.BookCategories.Any(bc => bc.Category.Name == categoryName))
                .Select(book => new
                {
                    book.BookId,
                    book.Title,
                    book.Description,
                    book.IsFree,
                    book.Status,
                    book.UploadDate,
                    Author = book.Author != null && book.Author.Reg != null
                        ? new
                        {
                            book.Author.UserId,
                            book.Author.Reg.UserName,
                            book.Author.Reg.Email
                        }
                        : null,
                    Files = book.BookFiles.Select(f => new
                    {
                        f.FileId,
                        f.PdfPath,
                        f.AudioPath,
                        f.FrontPageLink
                    }).ToList()
                })
                .ToList();

            if (books.Count == 0)
                return NotFound($"No books found under category: {categoryName}");

            return Ok(books);
        }
    }
}
