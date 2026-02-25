// File: Domain/Repositories/IUserRepository.cs
using System;
using System.Threading.Tasks;
using Domain.Entities;

namespace Domain.Repositories
{
    public interface IUserRepository
    {
        Task AddAsync(User user);
        Task<User?> GetByIdAsync(Guid id);
        Task<User?> GetByEmailAsync(string email);
        Task UpdateAsync(User user);
        Task DeleteAsync(Guid id);
    }
}