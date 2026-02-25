// File: Application/Services/AuthService.cs
using System;
using System.Threading.Tasks;
using Domain.Interfaces;

// Asumimos que estas interfaces (puertos) existen en el namespace Domain.Ports
// según el Blueprint para asegurar que la capa de Aplicación solo dependa de contratos de Dominio.
namespace Domain.Ports
{
    /// <summary>
    /// Puerto de salida para interactuar con un servicio de autenticación externo (adaptador HTTP).
    /// </summary>
    public interface IAuthenticationRepository
    {
        Task<string> AuthenticateAsync(string username, string password);
    }

    /// <summary>
    /// Puerto de entrada/salida para procesar tokens JWT.
    /// </summary>
    public interface IJwtProcessor
    {
        (string UserId, int NexusLevel, string SatelliteRole, DateTimeOffset Expiration) ProcessJwt(string jwtToken);
    }

    /// <summary>
    /// Puerto de salida para el almacenamiento seguro de tokens.
    /// </summary>
    public interface ITokenStorage
    {
        Task SaveTokenAsync(string token);
        Task<string> GetTokenAsync();
        Task ClearTokenAsync();
    }
}

namespace Application.Services
{
    /// <summary>
    /// Servicio de aplicación responsable de orquestar el flujo de autenticación,
    /// procesar JWT y gestionar la sesión del usuario.
    /// Depende de los puertos definidos en el dominio (IAuthenticationRepository, IJwtProcessor, ITokenStorage).
    /// </summary>
    public class AuthService
    {
        private readonly Domain.Ports.IAuthenticationRepository _authenticationRepository;
        private readonly Domain.Ports.IJwtProcessor _jwtProcessor;
        private readonly Domain.Ports.ITokenStorage _tokenStorage; // AuthService también necesita almacenar el token

        /// <summary>
        /// Implementación interna de INexusSession para la capa de aplicación.
        /// Esto permite que AuthService devuelva un objeto concreto que cumple con el contrato del dominio.
        /// </summary>
        private class NexusUserSession : INexusSession
        {
            public string UserId { get; }
            public int NexusLevel { get; }
            public string SatelliteRole { get; }
            public DateTimeOffset Expiration { get; }

            public NexusUserSession(string userId, int nexusLevel, string satelliteRole, DateTimeOffset expiration)
            {
                // Lecciones Aprendidas: Validar nulos en los constructores
                UserId = userId ?? throw new ArgumentNullException(nameof(userId));
                SatelliteRole = satelliteRole ?? throw new ArgumentNullException(nameof(satelliteRole));

                if (nexusLevel < 1 || nexusLevel > 6)
                    throw new ArgumentOutOfRangeException(nameof(nexusLevel), "NexusLevel must be between 1 and 6.");
                NexusLevel = nexusLevel;

                Expiration = expiration;
            }
        }

        public AuthService(
            Domain.Ports.IAuthenticationRepository authenticationRepository,
            Domain.Ports.IJwtProcessor jwtProcessor,
            Domain.Ports.ITokenStorage tokenStorage)
        {
            // Lecciones Aprendidas: Validar nulos en los constructores
            _authenticationRepository = authenticationRepository ?? throw new ArgumentNullException(nameof(authenticationRepository));
            _jwtProcessor = jwtProcessor ?? throw new ArgumentNullException(nameof(jwtProcessor));
            _tokenStorage = tokenStorage ?? throw new ArgumentNullException(nameof(tokenStorage));
        }

        /// <summary>
        /// Intenta autenticar a un usuario con las credenciales proporcionadas.
        /// </summary>
        /// <param name="username">Nombre de usuario.</param>
        /// <param name="password">Contraseña.</param>
        /// <returns>Una instancia de INexusSession si la autenticación es exitosa.</returns>
        /// <exception cref="ArgumentException">Se lanza si las credenciales son inválidas.</exception>
        /// <exception cref="ApplicationException">Se lanza si la autenticación falla o no se recibe token.</exception>
        /// <exception cref="UnauthorizedAccessException">Se lanza si el NexusLevel es inválido.</exception>
        public async Task<INexusSession> LoginAsync(string username, string password)
        {
            if (string.IsNullOrWhiteSpace(username)) throw new ArgumentException("Username cannot be empty.", nameof(username));
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentException("Password cannot be empty.", nameof(password));

            // 1. Consumir POST /api/auth/login a través del puerto de autenticación
            string jwtToken = await _authenticationRepository.AuthenticateAsync(username, password);
            if (string.IsNullOrEmpty(jwtToken))
            {
                throw new ApplicationException("Authentication failed: No token received from the API server.");
            }

            // 2. Procesar JWT y extraer Claims específicos (NexusLevel y SatelliteRole)
            (string userId, int nexusLevel, string satelliteRole, DateTimeOffset expiration) = _jwtProcessor.ProcessJwt(jwtToken);
            
            // 3. Validar NexusLevel en rango 1-6
            if (nexusLevel < 1 || nexusLevel > 6)
            {
                throw new UnauthorizedAccessException($"Invalid NexusLevel received: {nexusLevel}. Must be between 1 and 6.");
            }

            // 4. Coordinar almacenamiento seguro de credenciales (el JWT)
            await _tokenStorage.SaveTokenAsync(jwtToken);

            // 5. Devolver la sesión de usuario
            return new NexusUserSession(userId, nexusLevel, satelliteRole, expiration);
        }
        
        /// <summary>
        /// Recupera la sesión actual del token almacenado.
        /// </summary>
        /// <returns>Una instancia de INexusSession si existe un token válido, de lo contrario null.</returns>
        public async Task<INexusSession> GetCurrentSessionAsync()
        {
            string jwtToken = await _tokenStorage.GetTokenAsync();
            if (string.IsNullOrEmpty(jwtToken))
            {
                return null; // No hay token almacenado o está vacío
            }

            try
            {
                // Procesar el JWT almacenado para recrear la sesión
                (string userId, int nexusLevel, string satelliteRole, DateTimeOffset expiration) = _jwtProcessor.ProcessJwt(jwtToken);

                // Validar NexusLevel y la expiración si es posible
                if (nexusLevel < 1 || nexusLevel > 6 || expiration <= DateTimeOffset.UtcNow)
                {
                    // Token inválido o expirado, limpiar y devolver null
                    await _tokenStorage.ClearTokenAsync();
                    return null;
                }
                
                return new NexusUserSession(userId, nexusLevel, satelliteRole, expiration);
            }
            catch (Exception)
            {
                // Si hay algún error al procesar el JWT (ej. inválido, corrupto),
                // asumimos que el token no es válido y lo eliminamos.
                await _tokenStorage.ClearTokenAsync();
                return null;
            }
        }

        /// <summary>
        /// Cierra la sesión del usuario eliminando el token almacenado.
        /// </summary>
        public async Task LogoutAsync()
        {
            await _tokenStorage.ClearTokenAsync();
        }
    }
}