using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PenToPublic.Data;
using PenToPublic.DTOs;
using PenToPublic.Models;
using System.Linq;
using System.Threading.Tasks;

namespace PenToPublic.Controllers
{
    [ApiController]
    [Route("api/books")]
    public class BooksController : ControllerBase
    {
        private readonly PenToPublicContext _context;

        public BooksController(PenToPublicContext context)
        {
            _context = context;
        }

        // GET: api/books
        [HttpGet]
        [HttpGet]
        public async Task<IActionResult> GetAllBooks()
        {
            var books = await _context.Books
                .Include(b => b.Author)
                    .ThenInclude(a => a.Reg)
                .Include(b => b.Reviews)
                .ToListAsync(); // Fetch raw data into memory

            var result = books.Select(b => new
            {
                bookId = b.BookId,
                title = b.Title,
                description = b.Description,
                isFree = b.IsFree ?? false,
                status = b.Status ?? "Draft",
                uploadDate = (b.UploadDate ?? DateTime.Now).ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                isAudible = b.IsAudible,
                averageRating = b.Reviews.Any() ? (double?)b.Reviews.Average(r => r.Rating ?? 0) : null,
                totalReviews = b.Reviews.Count(),
                author = b.Author?.Reg != null ? new
                {
                    userId = b.Author.UserId,
                    role = b.Author.Role ?? "Author",
                    name = b.Author.Reg.UserName,
                    email = b.Author.Reg.Email
                } : null
            });

            return Ok(result);
        }

        // GET: api/books/recent
        [HttpGet("recent")]
        public async Task<IActionResult> GetRecentBooks()
        {
            var books = await _context.Books
                .Include(b => b.Author)
                    .ThenInclude(a => a.Reg)
                .Include(b => b.Reviews)
                .OrderByDescending(b => b.UploadDate)
                .Take(20)
                .Select(b => new
                {
                    bookId = b.BookId,
                    title = b.Title,
                    description = b.Description,
                    isFree = b.IsFree ?? false,
                    status = b.Status ?? "Draft",
                    uploadDate = (b.UploadDate ?? DateTime.Now).ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    isAudible = b.IsAudible,
                    averageRating = b.Reviews.Any() ? (double?)b.Reviews.Average(r => r.Rating ?? 0) : null,
                    totalReviews = b.Reviews.Count(),
                    author = b.Author == null ? null : new
                    {
                        userId = b.Author.UserId,
                        role = b.Author.Role ?? "Author",
                        name = b.Author.Reg != null ? b.Author.Reg.UserName : null,
                        email = b.Author.Reg != null ? b.Author.Reg.Email : null
                    }
                })
                .ToListAsync();

            return Ok(books);
        }

        // GET: api/books/top
        [HttpGet("top")]
        public async Task<IActionResult> GetTopBooks()
        {
            var books = await _context.Books
                .Include(b => b.Reviews)
                .Include(b => b.Author)
                    .ThenInclude(a => a.Reg)
                .Where(b => b.Reviews.Any())
                .Select(b => new
                {
                    bookId = b.BookId,
                    title = b.Title,
                    description = b.Description,
                    isFree = b.IsFree ?? false,
                    status = b.Status ?? "Draft",
                    uploadDate = (b.UploadDate ?? DateTime.Now).ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    isAudible = b.IsAudible,
                    averageRating = (double)b.Reviews.Average(r => r.Rating ?? 0),
                    totalReviews = b.Reviews.Count(),
                    author = b.Author == null ? null : new
                    {
                        userId = b.Author.UserId,
                        role = b.Author.Role ?? "Author",
                        name = b.Author.Reg != null ? b.Author.Reg.UserName : null,
                        email = b.Author.Reg != null ? b.Author.Reg.Email : null
                    }
                })
                .OrderByDescending(b => b.averageRating)
                .ThenByDescending(b => b.totalReviews)
                .Take(20)
                .ToListAsync();

            return Ok(books);
        }

        // GET: api/books/free
        [HttpGet("free")]
        public async Task<IActionResult> GetFreeBooks()
        {
            var books = await _context.Books
                .Where(b => b.IsFree == true)
                .Include(b => b.Author)
                    .ThenInclude(a => a.Reg)
                .Include(b => b.Reviews)
                .Select(b => new
                {
                    bookId = b.BookId,
                    title = b.Title,
                    description = b.Description,
                    isFree = b.IsFree ?? false,
                    status = b.Status ?? "Draft",
                    uploadDate = (b.UploadDate ?? DateTime.Now).ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    isAudible = b.IsAudible,
                    averageRating = b.Reviews.Any() ? (double?)b.Reviews.Average(r => r.Rating ?? 0) : null,
                    totalReviews = b.Reviews.Count(),
                    author = b.Author == null ? null : new
                    {
                        userId = b.Author.UserId,
                        role = b.Author.Role ?? "Author",
                        name = b.Author.Reg != null ? b.Author.Reg.UserName : null,
                        email = b.Author.Reg != null ? b.Author.Reg.Email : null
                    }
                })
                .ToListAsync();

            return Ok(books);
        }

        // GET: api/books/audible
        [HttpGet("audible")]
        public async Task<IActionResult> GetAudibleBooks()
        {
            var books = await _context.Books
                .Where(b => b.IsAudible == true)
                .Include(b => b.Author)
                    .ThenInclude(a => a.Reg)
                .Include(b => b.Reviews)
                .Select(b => new
                {
                    bookId = b.BookId,
                    title = b.Title,
                    description = b.Description,
                    isFree = b.IsFree ?? false,
                    status = b.Status ?? "Draft",
                    uploadDate = (b.UploadDate ?? DateTime.Now).ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    isAudible = b.IsAudible,
                    averageRating = b.Reviews.Any() ? (double?)b.Reviews.Average(r => r.Rating ?? 0) : null,
                    totalReviews = b.Reviews.Count(),
                    author = b.Author == null ? null : new
                    {
                        userId = b.Author.UserId,
                        role = b.Author.Role ?? "Author",
                        name = b.Author.Reg != null ? b.Author.Reg.UserName : null,
                        email = b.Author.Reg != null ? b.Author.Reg.Email : null
                    }
                })
                .ToListAsync();

            return Ok(books);
        }

        // GET: api/books/search?title=keyword
        [HttpGet("search")]
        public async Task<IActionResult> SearchBooks([FromQuery] string title)
        {
            if (string.IsNullOrWhiteSpace(title))
                return BadRequest("Title parameter is required.");

            var books = await _context.Books
                .Include(b => b.Author)
                    .ThenInclude(a => a.Reg)
                .Include(b => b.Reviews)
                .Where(b => b.Title.Contains(title))
                .Select(b => new
                {
                    bookId = b.BookId,
                    title = b.Title,
                    description = b.Description,
                    isFree = b.IsFree ?? false,
                    status = b.Status ?? "Draft",
                    uploadDate = (b.UploadDate ?? DateTime.Now).ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    isAudible = b.IsAudible,
                    averageRating = b.Reviews.Any() ? (double?)b.Reviews.Average(r => r.Rating ?? 0) : null,
                    totalReviews = b.Reviews.Count(),
                    author = b.Author == null ? null : new
                    {
                        userId = b.Author.UserId,
                        role = b.Author.Role ?? "Author",
                        name = b.Author.Reg != null ? b.Author.Reg.UserName : null,
                        email = b.Author.Reg != null ? b.Author.Reg.Email : null
                    }
                })
                .ToListAsync();

            return Ok(books);
        }

        // GET: api/books/author/{authorId}
        [HttpGet("author/{authorId}")]
        public async Task<IActionResult> GetBooksByAuthor(int authorId)
        {
            var books = await _context.Books
                .Include(b => b.Author)
                    .ThenInclude(a => a.Reg)
                .Include(b => b.Reviews)
                .Where(b => b.AuthorId == authorId)
                .Select(b => new
                {
                    bookId = b.BookId,
                    title = b.Title,
                    description = b.Description,
                    isFree = b.IsFree ?? false,
                    status = b.Status ?? "Draft",
                    uploadDate = (b.UploadDate ?? DateTime.Now).ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    isAudible = b.IsAudible,
                    averageRating = b.Reviews.Any() ? (double?)b.Reviews.Average(r => r.Rating ?? 0) : null,
                    totalReviews = b.Reviews.Count(),
                    author = b.Author == null ? null : new
                    {
                        userId = b.Author.UserId,
                        role = b.Author.Role ?? "Author",
                        name = b.Author.Reg != null ? b.Author.Reg.UserName : null,
                        email = b.Author.Reg != null ? b.Author.Reg.Email : null
                    }
                })
                .ToListAsync();

            return Ok(books);
        }

        // GET: api/books/author?name=authorname
        [HttpGet("author")]
        public async Task<IActionResult> GetBooksByAuthorName([FromQuery] string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return BadRequest("Author name is required.");

            var books = await _context.Books
                .Include(b => b.Author)
                    .ThenInclude(a => a.Reg)
                .Include(b => b.Reviews)
                .Where(b => b.Author != null &&
                            b.Author.Reg != null &&
                            b.Author.Reg.UserName.Contains(name))
                .ToListAsync();

            var result = books.Select(b => new
            {
                bookId = b.BookId,
                title = b.Title,
                description = b.Description,
                isFree = b.IsFree ?? false,
                status = b.Status ?? "Draft",
                uploadDate = (b.UploadDate ?? DateTime.Now).ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                isAudible = b.IsAudible,
                averageRating = b.Reviews.Any() ? b.Reviews.Average(r => r.Rating ?? 0) : 0,
                totalReviews = b.Reviews.Count(),
                author = b.Author != null && b.Author.Reg != null ? new
                {
                    userId = b.Author.UserId,
                    role = b.Author.Role ?? "Author",
                    name = b.Author.Reg.UserName,
                    email = b.Author.Reg.Email
                } : null
            });

            return Ok(result);
        }

        // GET: api/books/{id}
        [HttpGet("{id}")]
        public async Task<IActionResult> GetBookById(int id)
        {
            var book = await _context.Books
                .Include(b => b.Author)
                    .ThenInclude(a => a.Reg)
                .Include(b => b.Reviews)
                    .ThenInclude(r => r.User)
                        .ThenInclude(u => u.Reg)
                .Include(b => b.BookFiles)
                .FirstOrDefaultAsync(b => b.BookId == id);

            if (book == null)
                return NotFound();

            var bookDetail = new
            {
                bookId = book.BookId,
                title = book.Title,
                description = book.Description,
                isFree = book.IsFree ?? false,
                status = book.Status ?? "Draft",
                uploadDate = book.UploadDate?.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") ?? DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                isAudible = book.IsAudible,
                averageRating = book.Reviews.Any() ? (double?)book.Reviews.Average(r => r.Rating ?? 0) : null,
                totalReviews = book.Reviews.Count(),
                author = book.Author == null ? null : new
                {
                    userId = book.Author.UserId,
                    role = book.Author.Role ?? "Author",
                    name = book.Author.Reg != null ? book.Author.Reg.UserName : null,
                    email = book.Author.Reg != null ? book.Author.Reg.Email : null
                },
                bookFiles = book.BookFiles.Select(bf => new
                {
                    fileId = bf.FileId,
                    bookId = bf.BookId,
                    pdfPath = bf.PdfPath,
                    audioPath = bf.AudioPath,
                    frontPageLink = bf.FrontPageLink
                }).ToList(),
                reviews = book.Reviews.Select(r => new
                {
                    reviewId = r.ReviewId,
                    userId = r.UserId,
                    bookId = r.BookId,
                    rating = r.Rating ?? 0,
                    comment = r.Comment,
                    reviewedAt = r.ReviewedAt?.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") ?? DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    user = r.User?.Reg != null ? new
                    {
                        userName = r.User.Reg.UserName
                    } : null
                }).ToList()
            };

            return Ok(bookDetail);
        }

        [HttpGet("{bookId}/reviews")]
        public async Task<IActionResult> GetBookReviews(int bookId)
        {
            var reviews = await _context.Reviews
                .Include(r => r.User)
                    .ThenInclude(u => u.Reg)
                .Where(r => r.BookId == bookId)
                .OrderByDescending(r => r.ReviewedAt)
                .ToListAsync();

            var formattedReviews = reviews.Select(r => new
            {
                reviewId = r.ReviewId,
                userId = r.UserId,
                bookId = r.BookId,
                rating = r.Rating ?? 0,
                comment = r.Comment,
                reviewedAt = (r.ReviewedAt ?? DateTime.Now).ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                user = r.User != null && r.User.Reg != null
                    ? new
                    {
                        userName = r.User.Reg.UserName
                    }
                    : null
            });

            return Ok(formattedReviews);
        }


        // POST: api/books/{bookId}/reviews
        [HttpPost("{bookId}/reviews")]
        public async Task<IActionResult> SubmitReview(int bookId, [FromBody] ReviewRequest request)
        {
            if (request.Rating < 1 || request.Rating > 5)
                return BadRequest("Rating must be between 1 and 5.");

            var book = await _context.Books.FindAsync(bookId);
            if (book == null)
                return NotFound("Book not found.");

            var review = new Review
            {
                BookId = bookId,
                UserId = request.UserId,
                Rating = request.Rating,
                Comment = request.Comment,
                ReviewedAt = DateTime.UtcNow
            };

            _context.Reviews.Add(review);
            await _context.SaveChangesAsync();

            var createdReview = new
            {
                reviewId = review.ReviewId,
                userId = review.UserId,
                bookId = review.BookId,
                rating = review.Rating ?? 0,
                comment = review.Comment,
                reviewedAt = review.ReviewedAt?.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") ?? DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                user = new
                {
                    userName = "Current User"
                }
            };

            return CreatedAtAction(nameof(GetBookReviews), new { bookId }, createdReview);
        }

        // GET: api/books/{bookId}/progress/{userId}
        [HttpGet("{bookId}/progress/{userId}")]
        public async Task<IActionResult> GetReadingProgress(int bookId, int userId)
        {
            var progress = await _context.ReadingProgresses
                .FirstOrDefaultAsync(rp => rp.BookId == bookId && rp.UserId == userId);

            if (progress == null)
                return NotFound();

            var progressData = new
            {
                progressId = progress.ProgressId,
                userId = progress.UserId,
                bookId = progress.BookId,
                percentRead = (double)(progress.PercentRead ?? 0),
                lastPage = progress.LastPage ?? 1,
                totalPages = progress.TotalPages,
                updatedAt = progress.UpdatedAt?.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") ?? DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            };

            return Ok(progressData);
        }

        // PUT: api/books/{bookId}/progress/{userId}
        [HttpPut("{bookId}/progress/{userId}")]
        public async Task<IActionResult> UpdateReadingProgress(int bookId, int userId, [FromBody] ReadingProgressRequest request)
        {
            var progress = await _context.ReadingProgresses
                .FirstOrDefaultAsync(rp => rp.BookId == bookId && rp.UserId == userId);

            if (progress == null)
            {
                progress = new ReadingProgress
                {
                    BookId = bookId,
                    UserId = userId,
                    LastPage = request.LastPage,
                    PercentRead = (decimal)request.PercentRead,
                    TotalPages = request.TotalPages,
                    UpdatedAt = DateTime.UtcNow
                };
                _context.ReadingProgresses.Add(progress);
            }
            else
            {
                progress.LastPage = request.LastPage;
                progress.PercentRead = (decimal)request.PercentRead;
                progress.TotalPages = request.TotalPages;
                progress.UpdatedAt = DateTime.UtcNow;
            }

            await _context.SaveChangesAsync();

            var progressData = new
            {
                progressId = progress.ProgressId,
                userId = progress.UserId,
                bookId = progress.BookId,
                percentRead = (double)(progress.PercentRead ?? 0),
                lastPage = progress.LastPage ?? 1,
                totalPages = progress.TotalPages,
                updatedAt = progress.UpdatedAt?.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") ?? DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            };

            return Ok(progressData);
        }

        // GET: api/books/with-all-files
        [HttpGet("with-all-files")]
        public async Task<IActionResult> GetAllBooksWithAllFileInfo()
        {
            var books = await _context.Books
                .Include(b => b.BookFiles)
                .Include(b => b.Author)
                    .ThenInclude(a => a.Reg)
                .Include(b => b.Reviews)
                .Select(b => new
                {
                    bookId = b.BookId,
                    title = b.Title,
                    description = b.Description,
                    isFree = b.IsFree ?? false,
                    status = b.Status ?? "Draft",
                    uploadDate = (b.UploadDate ?? DateTime.Now).ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    isAudible = b.IsAudible,
                    averageRating = b.Reviews.Any() ? (double?)b.Reviews.Average(r => r.Rating ?? 0) : null,
                    totalReviews = b.Reviews.Count(),
                    author = b.Author != null && b.Author.Reg != null ? new
                    {
                        userId = b.Author.UserId,
                        role = b.Author.Role ?? "Author",
                        name = b.Author.Reg.UserName,
                        email = b.Author.Reg.Email
                    } : null,
                    bookFiles = b.BookFiles.Select(f => new
                    {
                        fileId = f.FileId,
                        bookId = f.BookId,
                        pdfPath = f.PdfPath,
                        audioPath = f.AudioPath,
                        frontPageLink = f.FrontPageLink
                    }).ToList()
                })
                .ToListAsync();

            return Ok(books);
        }




    }
}
