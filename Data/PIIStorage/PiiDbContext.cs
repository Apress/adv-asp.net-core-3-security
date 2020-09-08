using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Data.PIIStorage
{
    public partial class PiiDbContext : DbContext
    {
        private string _connectionString;

        public PiiDbContext()
        {
        }

        public PiiDbContext(DbContextOptions<PiiDbContext> options)
            : base(options)
        {
        }

        public PiiDbContext(string connectionString) : base()
        {
            _connectionString = connectionString;
        }

        public virtual DbSet<AspNetUsers> AspNetUsers { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlServer(_connectionString);
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<AspNetUsers>(entity =>
            {
                entity.ToTable("AspNetUsers", "pii");

                entity.Property(e => e.Email).HasMaxLength(1000);

                entity.Property(e => e.UserName).HasMaxLength(1000);

                entity.Property(e => e.NormalizedEmail).HasMaxLength(1000);

                entity.Property(e => e.NormalizedUserName).HasMaxLength(1000);

                entity.Property(e => e.PhoneNumber).HasMaxLength(1000);
            });

            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}
