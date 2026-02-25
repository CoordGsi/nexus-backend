// File: Infrastructure/Controllers/TestAuthController.cs
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc; // Required for Controller, ApiController, etc.
using Application.Interfaces;   // To use ITestAuthService (Application Port)
using System;

namespace Infrastructure.DTOs
{
    /// <summary>
    /// Data Transfer Object for user login requests.
    /// Used by the API controller to receive credentials from the client.
    /// </summary>
    public class LoginRequest
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    /// <summary>
    /// Data Transfer Object for user login responses.
    /// Used by the API controller to send the generated JWT back to the client.
    /// </summary>
    public class LoginResponse
    {
        public string Token { get; }

        public LoginResponse(string token)
        {
            Token = token ?? throw new ArgumentNullException(nameof(token));
        }
    }
}

namespace Infrastructure.Controllers
{
    /// <summary>
    /// API Controller for authentication operations.
    /// Acts as an adapter, receiving external requests and invoking the Application layer's services (ports).
    /// </summary>
    [ApiController]
    [Route("auth")] // Base route for this controller
    public class TestAuthController : ControllerBase
    {
        private readonly ITestAuthService _testAuthService;

        /// <summary>
        /// Initializes a new instance of the <see cref="TestAuthController"/> class.
        /// The <see cref="ITestAuthService"/> (Application Port) is injected here.
        /// </summary>
        /// <param name="testAuthService">The authentication service from the Application layer.</param>
        public TestAuthController(ITestAuthService testAuthService)
        {
            _testAuthService = testAuthService ?? throw new ArgumentNullException(nameof(testAuthService));
        }

        /// <summary>
        /// Handles user login requests.
        /// Endpoint: POST /auth/login
        /// </summary>
        /// <param name="request">The login request containing email and password.</param>
        /// <returns>
        /// An <see cref="IActionResult"/> containing a JWT on successful login (HTTP 200 OK),
        /// or an error response (HTTP 401 Unauthorized or HTTP 400 Bad Request).
        /// </returns>
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] DTOs.LoginRequest request)
        {
            // Basic model state validation provided by ASP.NET Core MVC.
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Invoke the Application layer's authentication service (port).
            string? token = await _testAuthService.LoginAsync(request.Email, request.Password);

            if (token == null)
            {
                // If the service returns null, it means authentication failed (e.g., invalid credentials).
                return Unauthorized(new { Message = "Invalid credentials." });
            }

            // On successful authentication, return the JWT token.
            return Ok(new DTOs.LoginResponse(token));
        }
    }
}