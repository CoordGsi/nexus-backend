// File: Domain/Repositories/IUserRepository.cs
using Domain.Entities;
using System.Threading.Tasks;

namespace Domain.Repositories
{
    public interface IUserRepository
    {
        Task<User> GetByEmailAsync(string email);
        Task<User> CreateAsync(User user);
        Task<bool> ExistsAsync(string email);
    }
}