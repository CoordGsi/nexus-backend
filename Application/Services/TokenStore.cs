// File: Application/Services/TokenStore.cs
using System;
using System.Threading.Tasks;
// Asumimos que la interfaz ITokenStorage existe en el namespace Domain.Ports
// según el Blueprint para asegurar que la capa de Aplicación solo dependa de contratos de Dominio.
using Domain.Ports;

namespace Application.Services
{
    /// <summary>
    /// Servicio de aplicación para gestionar el ciclo de vida de los tokens JWT,
    /// utilizando el puerto ITokenStorage para la persistencia segura.
    /// </summary>
    public class TokenStore
    {
        private readonly ITokenStorage _tokenStorage;

        public TokenStore(ITokenStorage tokenStorage)
        {
            // Lecciones Aprendidas: Validar nulos en los constructores
            _tokenStorage = tokenStorage ?? throw new ArgumentNullException(nameof(tokenStorage));
        }

        /// <summary>
        /// Guarda un token de forma segura.
        /// </summary>
        /// <param name="token">El token JWT a guardar.</param>
        /// <returns>Una tarea que representa la operación asíncrona.</returns>
        /// <exception cref="ArgumentException">Se lanza si el token es nulo o vacío.</exception>
        public async Task SaveTokenAsync(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                throw new ArgumentException("Token cannot be null or empty.", nameof(token));
            }
            // Delegate la operación de guardado al adaptador a través del puerto
            await _tokenStorage.SaveTokenAsync(token);
        }

        /// <summary>
        /// Recupera el token guardado de forma segura.
        /// </summary>
        /// <returns>El token JWT, o null si no hay ninguno.</returns>
        public async Task<string> GetTokenAsync()
        {
            // Delegate la operación de recuperación al adaptador a través del puerto
            return await _tokenStorage.GetTokenAsync();
        }

        /// <summary>
        /// Elimina el token guardado de forma segura.
        /// </summary>
        /// <returns>Una tarea que representa la operación asíncrona.</returns>
        public async Task ClearTokenAsync()
        {
            // Delegate la operación de limpieza al adaptador a través del puerto
            await _tokenStorage.ClearTokenAsync();
        }
    }
}