// El paquete api contiene las estructuras necesarias
// para la comunicación entre servidor y cliente.
package api

const (
	ActionRegister   = "register"
	ActionLogin      = "login"
	ActionFetchData  = "fetchData"
	ActionUpdateData = "updateData"
	ActionLogout     = "logout"
	ActionModData    = "modData"
	ActionDelData    = "delData"
	ActionGetID      = "getID"
)

// Request y Response como antes
type Request struct {
	Action   string `json:"action"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
	Data     string `json:"data,omitempty"`
	PubKey   string `json:"pubKey,omitempty"`
	PriKey   string `json:"priKey,omitempty"`
	Position int    `json:"position,omitempty"`
}

type Response struct {
	Success bool     `json:"success"`
	Message string   `json:"message"`
	Token   string   `json:"token,omitempty"`
	Data    []string `json:"data,omitempty"`
	ID      int      `json:"id,omitempty"`
}

type ClinicData struct {
	ID          int
	Name        string
	SureName    string
	Edad        int
	Sexo        string
	SIP         int
	Procedencia string
	Motivo      string
	Enfermedad  string
}
