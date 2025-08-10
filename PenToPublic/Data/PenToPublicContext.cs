using Microsoft.EntityFrameworkCore;
using PenToPublic.Models;

namespace PenToPublic.Data
{
    public class PenToPublicContext : DbContext
    {
        public PenToPublicContext(DbContextOptions<PenToPublicContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; } = default!;
        public DbSet<Registration> Registrations { get; set; } = default!;
        public DbSet<AuthorDetail> AuthorDetails { get; set; } = default!;
        public DbSet<ReaderDetail> ReaderDetails { get; set; } = default!;
        public DbSet<Book> Books { get; set; } = default!;
        public DbSet<BookFile> BookFiles { get; set; }
        public DbSet<Category> Categories { get; set; } = default!;
        public DbSet<BookCategory> BookCategories { get; set; } = default!;
        public DbSet<Admin> Admins { get; set; } = default!;
        public DbSet<ReadingProgress> ReadingProgresses { get; set; } = default!;
        public DbSet<AdminApproval> AdminApprovals { get; set; }
        public DbSet<Review> Reviews { get; set; } = default!;
        public DbSet<Payment> Payments { get; set; }
        public virtual DbSet<OtpEntry> OtpEntries { get; set; }
        public object Readers { get; internal set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // One-to-one: User ↔ Registration
            modelBuilder.Entity<User>()
                .HasOne(u => u.Reg)
                .WithOne(r => r.User)
                .HasForeignKey<User>(u => u.RegId)
                .OnDelete(DeleteBehavior.Cascade);

            // One-to-one: User ↔ AuthorDetail
            modelBuilder.Entity<AuthorDetail>()
                .HasOne(ad => ad.User)
                .WithOne(u => u.AuthorDetail)
                .HasForeignKey<AuthorDetail>(ad => ad.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // One-to-one: User ↔ ReaderDetail
            modelBuilder.Entity<ReaderDetail>()
                .HasOne(rd => rd.User)
                .WithOne(u => u.ReaderDetail)
                .HasForeignKey<ReaderDetail>(rd => rd.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
