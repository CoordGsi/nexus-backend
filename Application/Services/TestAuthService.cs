// File: Application/Services/TestAuthService.cs
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Domain.Interfaces;        // To use IAuthTestRepository (Port)
using Domain.Entities;          // To use User entity
using Domain.ValueObjects;      // To use Email and Password value objects

namespace Application.Interfaces
{
    /// <summary>
    /// Port definition for generating JSON Web Tokens.
    /// The Application layer depends on this abstraction, not a concrete implementation.
    /// </summary>
    public interface IJwtTokenGenerator
    {
        /// <summary>
        /// Generates a JWT with specified user claims.
        /// </summary>
        /// <param name="userId">The unique identifier of the user.</param>
        /// <param name="nexusLevel">The NexusLevel of the user.</param>
        /// <param name="satelliteRole">The derived SatelliteRole for the user.</param>
        /// <returns>A string representing the generated JWT.</returns>
        string GenerateToken(Guid userId, int nexusLevel, string satelliteRole);
    }

    /// <summary>
    /// Port definition for the core authentication service.
    /// This defines the contract for authentication operations in the Application layer.
    /// </summary>
    public interface ITestAuthService
    {
        /// <summary>
        /// Attempts to log in a user with the given email and password.
        /// </summary>
        /// <param name="emailString">The user's email as a string.</param>
        /// <param name="passwordString">The user's password as a string.</param>
        /// <returns>A JWT string if authentication is successful; otherwise, null.</returns>
        Task<string?> LoginAsync(string emailString, string passwordString);
    }
}

namespace Application.Services
{
    /// <summary>
    /// Adapter implementation for the <see cref="ITestAuthService"/> port.
    /// It orchestrates domain logic and interacts with other ports (repositories, token generators).
    /// </summary>
    public class TestAuthService : Interfaces.ITestAuthService
    {
        private readonly IAuthTestRepository _authTestRepository;
        private readonly Interfaces.IJwtTokenGenerator _jwtTokenGenerator;

        /// <summary>
        /// Initializes a new instance of the <see cref="TestAuthService"/> class.
        /// Dependencies (ports) are injected via the constructor.
        /// </summary>
        /// <param name="authTestRepository">The repository port for user data access.</param>
        /// <param name="jwtTokenGenerator">The JWT token generator port.</param>
        public TestAuthService(IAuthTestRepository authTestRepository, Interfaces.IJwtTokenGenerator jwtTokenGenerator)
        {
            _authTestRepository = authTestRepository ?? throw new ArgumentNullException(nameof(authTestRepository));
            _jwtTokenGenerator = jwtTokenGenerator ?? throw new ArgumentNullException(nameof(jwtTokenGenerator));
        }

        /// <summary>
        /// Implements the login functionality.
        /// Validates credentials, retrieves user data, maps NexusLevel to SatelliteRole,
        /// and generates a JWT.
        /// </summary>
        /// <param name="emailString">The user's email.</param>
        /// <param name="passwordString">The user's password.</param>
        /// <returns>A JWT string on successful login, or null if credentials are invalid.</returns>
        public async Task<string?> LoginAsync(string emailString, string passwordString)
        {
            // Convert raw input strings into Domain Value Objects.
            // This ensures domain invariants (e.g., email format) are checked at the application boundary.
            Email email;
            Password password;
            try
            {
                email = new Email(emailString);
                password = new Password(passwordString);
            }
            catch (ArgumentException)
            {
                // If value object creation fails (e.g., invalid email format), authentication fails.
                // Do not expose specific reasons to prevent information disclosure.
                return null;
            }

            // Use the IAuthTestRepository (Domain Port) to find the user.
            User? user = await _authTestRepository.GetUserByCredentialsAsync(email, password);

            if (user == null)
            {
                // User not found or credentials do not match.
                return null;
            }

            // Map NexusLevel to SatelliteRole as per blueprint requirement for the Application layer.
            string satelliteRole = MapNexusLevelToSatelliteRole(user.NexusLevel);

            // Use the IJwtTokenGenerator (Application Port) to create the token with required claims.
            string token = _jwtTokenGenerator.GenerateToken(user.UserId, user.NexusLevel, satelliteRole);

            return token;
        }

        /// <summary>
        /// Maps a NexusLevel integer to its corresponding SatelliteRole string.
        /// </summary>
        /// <param name="nexusLevel">The NexusLevel of the user (1-6).</param>
        /// <returns>The corresponding SatelliteRole string.</returns>
        private static string MapNexusLevelToSatelliteRole(int nexusLevel)
        {
            return nexusLevel switch
            {
                1 => "Cadet",
                2 => "Pilot",
                3 => "Commander",
                4 => "Navigator",
                5 => "Strategist",
                6 => "Sentinel",
                _ => "Unknown", // Handle unexpected levels gracefully.
            };
        }
    }
}