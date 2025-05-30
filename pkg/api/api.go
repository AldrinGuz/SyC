// El paquete api contiene las estructuras necesarias
// para la comunicación entre servidor y cliente.
package api

const (
	ActionRegister   = "register"
	ActionLogin      = "login"
	ActionGetData    = "fetchData"
	ActionPostData   = "addData"
	ActionLogout     = "logout"
	ActionPutData    = "modData"
	ActionDeleteData = "delData"
	ActionGetID      = "getID"
	ActionEnable2FA  = "enable-2fa"
	ActionDisable2FA = "disable-2fa"
	ActionVerify2FA  = "verify-2fa"
)

// Request contiene todos los campos posibles para las solicitudes al servidor
type Request struct {
	Action      string `json:"action"`                 // Acción a realizar
	Username    string `json:"username"`               // Nombre de usuario
	Password    string `json:"password,omitempty"`     // Contraseña (omitida en algunas acciones)
	Token       string `json:"token,omitempty"`        // Token de autenticación
	Data        string `json:"data,omitempty"`         // Datos adicionales
	PubKey      string `json:"pubKey,omitempty"`       // Clave pública
	PriKey      string `json:"priKey,omitempty"`       // Clave privada
	Position    int    `json:"position,omitempty"`     // Posición en listas
	TOTPCode    string `json:"totp_code,omitempty"`    // Código de autenticación de dos factores
	Action2FA   string `json:"action_2fa,omitempty"`   // Acción específica para 2FA
	Requires2FA bool   `json:"requires_2fa,omitempty"` // Indica si se requiere 2FA
	SIP         string `json:"sip,omitempty"`
}

// Response contiene la respuesta del servidor a las solicitudes
type Response struct {
	Success     bool                   `json:"success"`                // Indica si la operación fue exitosa
	Message     string                 `json:"message"`                // Mensaje descriptivo
	Token       string                 `json:"token,omitempty"`        // Token de autenticación
	Data        []string               `json:"data,omitempty"`         // Datos de respuesta
	ID          int                    `json:"id,omitempty"`           // ID generado
	Requires2FA bool                   `json:"requires_2fa,omitempty"` // Indica si se requiere 2FA
	DataMap     map[string]interface{} `json:"data_map,omitempty"`     // Datos adicionales en formato mapa
	Rol         Rol                    `json:"rol,omitempty"`          // Se le asigna un rol
	Keys        []string               `json:"keys,omitempty"`         // Solicita las llaves para desencriptar los exp
}

// ClinicData estructura para los datos médicos
type ClinicData struct {
	ID          int    `json:"id"`          // Identificador único
	Name        string `json:"name"`        // Nombre del paciente
	SureName    string `json:"surename"`    // Apellidos del paciente
	Edad        int    `json:"edad"`        // Edad del paciente
	Sexo        string `json:"sexo"`        // Género del paciente
	SIP         int    `json:"sip"`         // Número SIP
	Procedencia string `json:"procedencia"` // Lugar de procedencia
	Motivo      string `json:"motivo"`      // Motivo de la consulta
	Enfermedad  string `json:"enfermedad"`  // Enfermedad diagnosticada
}

// 2FASetup contiene la información para configurar la autenticación en dos factores
type TwoFASetup struct {
	QRCode string `json:"qr_code"` // Código QR en base64
	Secret string `json:"secret"`  // Secreto para configuración manual
}

type Rol struct {
	Name  string `json:"name"`
	Level int    `json:"level"`
}
