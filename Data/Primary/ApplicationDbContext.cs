using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Data.Primary
{
    public partial class ApplicationDbContext : IdentityDbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<CsrfToken>(entity =>
            {
                entity.ToTable("CSRFToken");

                entity.Property(e => e.CsrfTokenId)
                    .HasColumnName("CSRFTokenID")
                    .ValueGeneratedNever();

                entity.Property(e => e.ExpiresOn).HasColumnType("datetime");

                entity.Property(e => e.TokenValidOnPage)
                    .IsRequired()
                    .HasMaxLength(100)
                    .IsUnicode(false);
            });

            modelBuilder.Entity<Food>(entity =>
            {
                entity.Property(e => e.FoodId)
                    .HasColumnName("FoodID")
                    .ValueGeneratedNever();

                entity.Property(e => e.FoodGroupId).HasColumnName("FoodGroupID");

                entity.Property(e => e.FoodName)
                    .IsRequired()
                    .HasMaxLength(200);
            });

            modelBuilder.Entity<Order>(entity =>
            {
                entity.Property(e => e.OrderDate)
                    .HasColumnType("datetime")
                    .HasDefaultValueSql("(getdate())");

                entity.Property(e => e.UserId)
                    .IsRequired()
                    .HasMaxLength(450);
            });

            modelBuilder.Entity<OrderDetail>(entity =>
            {
                entity.Property(e => e.ProductName)
                    .IsRequired()
                    .HasMaxLength(100);

                entity.HasOne(d => d.Order)
                    .WithMany(p => p.OrderDetail)
                    .HasForeignKey(d => d.OrderId)
                    .OnDelete(DeleteBehavior.ClientSetNull)
                    .HasConstraintName("FK_OrderDetail_Order");
            });

            modelBuilder.Entity<PasswordHistory>(entity =>
            {
                entity.Property(e => e.CreatedOn).HasColumnType("datetime");

                entity.Property(e => e.ExpiresOn).HasColumnType("datetime");

                entity.Property(e => e.PasswordHash).IsRequired();

                entity.Property(e => e.UserId)
                    .IsRequired()
                    .HasMaxLength(450);
            });

            modelBuilder.Entity<SecurityEventLog>(entity =>
            {
                entity.Property(e => e.SecurityEventLogId).HasColumnName("SecurityEventLogID");

                entity.Property(e => e.CreatedDateTime).HasColumnType("datetime");

                entity.Property(e => e.LoggedInUserId)
                    .HasColumnName("LoggedInUserID")
                    .HasMaxLength(450);

                entity.Property(e => e.RequestIpaddress)
                    .HasColumnName("RequestIPAddress")
                    .HasMaxLength(255);

                entity.Property(e => e.RequestPath).HasMaxLength(255);

                entity.Property(e => e.RequestQuery).HasMaxLength(255);

                entity.Property(e => e.UserAgent).HasMaxLength(1000);
            });

            modelBuilder.Entity<UserSession>(entity =>
            {
                entity.Property(e => e.UserSessionId).ValueGeneratedNever();

                entity.Property(e => e.ExpiresOn).HasColumnType("datetime");

                entity.Property(e => e.UserId)
                    .IsRequired()
                    .HasMaxLength(450);
            });
        }

        public virtual DbSet<CsrfToken> CsrfToken { get; set; }
        public virtual DbSet<Food> Food { get; set; }
        public virtual DbSet<Order> Order { get; set; }
        public virtual DbSet<OrderDetail> OrderDetail { get; set; }
        public virtual DbSet<PasswordHistory> PasswordHistory { get; set; }
        public virtual DbSet<SecurityEventLog> SecurityEventLog { get; set; }
        public virtual DbSet<UserSession> UserSession { get; set; }
    }
}
