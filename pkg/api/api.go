// El paquete api contiene las estructuras necesarias
// para la comunicación entre servidor y cliente.
package api

const (
	ActionRegister   = "register"
	ActionLogin      = "login"
	ActionFetchData  = "fetchData"
	ActionUpdateData = "updateData"
	ActionLogout     = "logout"
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
}

type Response struct {
	Success bool     `json:"success"`
	Message string   `json:"message"`
	Token   string   `json:"token,omitempty"`
	Data    []string `json:"data,omitempty"`
}

type ClinicData struct {
	Name        string
	SureName    string
	ID          int
	NumHisClin  int
	Edad        int
	Sexo        string
	EstadoCivil string
	Ocupacion   string
	Procedencia string
	Motivo      string
	Enfermedad  string
}
