using FormulaOneApp.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace FormulaOneApp.Data
{
    public class AppDbContext : IdentityDbContext
    {
        public DbSet<Models.RefreshToken> RefreshTokens { get; set; }
        public DbSet<ChatMessage> ChatMessages { get; set; }
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
    }
}
