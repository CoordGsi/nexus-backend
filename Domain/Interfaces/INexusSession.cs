// File: Domain/Interfaces/INexusSession.cs
using System;

namespace Domain.Interfaces
{
    /// <summary>
    /// Define el contrato puro para una sesión de usuario en el dominio Nexus.
    /// Esta interfaz no debe tener dependencias de infraestructura ni de aplicación.
    /// </summary>
    public interface INexusSession
    {
        /// <summary>
        /// Obtiene el identificador único del usuario asociado a esta sesión.
        /// </summary>
        string UserId { get; }

        /// <summary>
        /// Obtiene el nivel de autorización Nexus del usuario (rango 1-6).
        /// </summary>
        int NexusLevel { get; }

        /// <summary>
        /// Obtiene el rol específico del satélite para el usuario.
        /// </summary>
        string SatelliteRole { get; }

        /// <summary>
        /// Obtiene la fecha y hora de expiración de la sesión.
        /// </summary>
        DateTimeOffset Expiration { get; }
    }
}