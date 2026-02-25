// File: Domain/Interfaces/IAuthTestRepository.cs
using System;
using System.Threading.Tasks;

// Define necessary Domain entities and value objects for the interface to compile.
// These are fundamental to the Domain layer and are used by the repository contract.

namespace Domain.Entities
{
    /// <summary>
    /// Represents a user entity within the Domain layer.
    /// Properties are read-only to ensure immutability after creation.
    /// </summary>
    public class User
    {
        public Guid UserId { get; }
        public Email Email { get; }
        public Password Password { get; } // Stored for authentication purposes, not to be exposed directly.
        public int NexusLevel { get; }

        public User(Guid userId, Email email, Password password, int nexusLevel)
        {
            UserId = userId == Guid.Empty ? throw new ArgumentException("User ID cannot be empty.", nameof(userId)) : userId;
            Email = email ?? throw new ArgumentNullException(nameof(email));
            Password = password ?? throw new ArgumentNullException(nameof(password));
            NexusLevel = nexusLevel;
            if (NexusLevel < 1 || NexusLevel > 6) // Basic validation for NexusLevel as per blueprint (1-6)
            {
                throw new ArgumentOutOfRangeException(nameof(nexusLevel), "NexusLevel must be between 1 and 6.");
            }
        }
    }
}

namespace Domain.ValueObjects
{
    /// <summary>
    /// Represents an email address as a value object.
    /// Ensures basic format validation and immutability.
    /// </summary>
    public record Email
    {
        public string Value { get; }

        public Email(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                throw new ArgumentException("Email cannot be null or empty.", nameof(value));
            // Basic email format validation. Can be enhanced with regex in a real application.
            if (!value.Contains("@") || !value.Contains("."))
                throw new ArgumentException("Invalid email format.", nameof(value));
            Value = value;
        }

        public override string ToString() => Value;
    }

    /// <summary>
    /// Represents a password as a value object.
    /// For this exercise, it stores plain text. In a real application, it should store a hash.
    /// </summary>
    public record Password
    {
        public string Value { get; } // Storing plain text for this exercise's hardcoded scenario.

        public Password(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                throw new ArgumentException("Password cannot be null or empty.", nameof(value));
            // Add password strength validation if necessary in a real application.
            Value = value;
        }

        public override string ToString() => "********"; // Mask the actual password value.
    }
}

namespace Domain.Interfaces
{
    /// <summary>
    /// Port definition for accessing authentication-related data.
    /// This interface specifies what the Domain needs from a data source,
    /// without knowing the concrete implementation (e.g., database, in-memory).
    /// </summary>
    public interface IAuthTestRepository
    {
        /// <summary>
        /// Attempts to retrieve a user based on provided email and password credentials.
        /// </summary>
        /// <param name="email">The user's email value object.</param>
        /// <param name="password">The user's password value object.</param>
        /// <returns>A <see cref="Domain.Entities.User"/> object if credentials are valid; otherwise, null.</returns>
        Task<Entities.User?> GetUserByCredentialsAsync(ValueObjects.Email email, ValueObjects.Password password);
    }
}