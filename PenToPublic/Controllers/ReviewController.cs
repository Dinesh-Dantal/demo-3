using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PenToPublic.Data;
using PenToPublic.Models;

namespace PenToPublic.Controllers
{
    [ApiController]
    [Route("api/reviews")]
    public class ReviewController : ControllerBase
    {
        private readonly PenToPublicContext _context;

        public ReviewController(PenToPublicContext context)
        {
            _context = context;
        }

        // ✅ GET: Get all reviews for a book
        [HttpGet("book/{bookId}")]
        public async Task<IActionResult> GetReviewsByBook(int bookId)
        {
            var reviews = await _context.Reviews
                .Where(r => r.BookId == bookId)
                .Include(r => r.User)
                .ThenInclude(u => u.Reg)
                .Select(r => new
                {
                    r.ReviewId,
                    r.Rating,
                    r.Comment,
                    r.ReviewedAt,
                    Reviewer = r.User != null && r.User.Reg != null ? new
                    {
                        r.User.UserId,
                        UserName = r.User.Reg.UserName,
                        Email = r.User.Reg.Email
                    } : null
                })
                .ToListAsync();

            return Ok(reviews);
        }

        // ✅ POST: Add a new review
        [HttpPost]
        public async Task<IActionResult> AddReview([FromBody] Review newReview)
        {
            if (newReview.UserId == null || newReview.BookId == null)
                return BadRequest("UserId and BookId are required.");

            if (newReview.Rating == null || newReview.Rating < 1 || newReview.Rating > 5)
                return BadRequest("Rating must be between 1 and 5.");

            var userExists = await _context.Users.AnyAsync(u => u.UserId == newReview.UserId);
            var bookExists = await _context.Books.AnyAsync(b => b.BookId == newReview.BookId);

            if (!userExists || !bookExists)
                return BadRequest("Invalid UserId or BookId.");

            newReview.ReviewedAt = DateTime.Now;
            _context.Reviews.Add(newReview);
            await _context.SaveChangesAsync();

            return Ok(new { message = "Review added successfully." });
        }

        // ✅ DELETE: Remove a review
        [HttpDelete("{reviewId}")]
        public async Task<IActionResult> DeleteReview(int reviewId)
        {
            var review = await _context.Reviews.FindAsync(reviewId);
            if (review == null)
                return NotFound(new { message = "Review not found." });

            _context.Reviews.Remove(review);
            await _context.SaveChangesAsync();

            return Ok(new { message = "Review deleted successfully." });
        }

        // ✅ PUT: Update a review
        [HttpPut("{reviewId}")]
        public async Task<IActionResult> UpdateReview(int reviewId, [FromBody] Review updatedReview)
        {
            var review = await _context.Reviews.FindAsync(reviewId);
            if (review == null)
                return NotFound(new { message = "Review not found." });

            if (updatedReview.Rating != null && (updatedReview.Rating < 1 || updatedReview.Rating > 5))
                return BadRequest("Rating must be between 1 and 5.");

            review.Rating = updatedReview.Rating ?? review.Rating;
            review.Comment = updatedReview.Comment ?? review.Comment;
            review.ReviewedAt = DateTime.Now;

            await _context.SaveChangesAsync();

            return Ok(new { message = "Review updated successfully." });
        }

        // ✅ GET: Average rating for a book
        [HttpGet("book/{bookId}/average")]
        public async Task<IActionResult> GetAverageRating(int bookId)
        {
            var ratings = await _context.Reviews
                .Where(r => r.BookId == bookId && r.Rating != null)
                .Select(r => r.Rating.Value)
                .ToListAsync();

            if (!ratings.Any())
                return Ok(new { bookId, averageRating = 0, message = "No ratings yet." });

            double average = ratings.Average();

            return Ok(new
            {
                bookId,
                averageRating = Math.Round(average, 2),
                totalReviews = ratings.Count
            });
        }
    }
}
