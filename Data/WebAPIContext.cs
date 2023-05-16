using Microsoft.EntityFrameworkCore;
using NetCore.Models;

namespace NetCore.Data
{
    public class WebAPIContext : DbContext
    {

        public WebAPIContext(DbContextOptions<WebAPIContext> options) : base(options)
        {

        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.UseSerialColumns();
        }

        public DbSet<User> Users { get; set; }
    }
}