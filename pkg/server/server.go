// server.go
package server

import (
	"SyC/pkg/api"
	"SyC/pkg/store"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// server encapsula el estado de nuestro servidor
type server struct {
	db  store.Store // base de datos
	log *log.Logger // logger para mensajes de error e información
}

// TokenInfo contiene el token y su tiempo de expiración
type TokenInfo struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

var key []byte

// Run inicia la base de datos y arranca el servidor HTTP.
func Run(n1 string) error {
	hash := sha256.Sum256([]byte(n1))
	key = hash[:]

	// Abrimos la base de datos usando el motor bbolt
	db, err := store.NewStore("bbolt", "data/server.db")
	if err != nil {
		return fmt.Errorf("error abriendo base de datos: %v", err)
	}

	// Creamos nuestro servidor con su logger con prefijo 'srv'
	srv := &server{
		db:  db,
		log: log.New(os.Stdout, "[srv] ", log.LstdFlags),
	}

	// Al terminar, cerramos la base de datos
	defer srv.db.Close()

	// Construimos un mux y asociamos /api a nuestro apiHandler,
	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	// Iniciamos el servidor HTTP.
	err = http.ListenAndServeTLS(":8080", "pkg/server/cert.pem", "pkg/server/key.pem", mux)
	return err
}

// apiHandler descodifica la solicitud JSON, la despacha
// a la función correspondiente y devuelve la respuesta JSON.
func (s *server) apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Decodificamos la solicitud en una estructura api.Request
	var req api.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}

	// Despacho según la acción solicitada
	var res api.Response
	switch req.Action {
	case api.ActionRegister:
		res = s.registerUser(req)
	case api.ActionLogin:
		res = s.loginUser(req)
	case api.ActionFetchData:
		res = s.fetchData(req)
	case api.ActionUpdateData:
		res = s.updateData(req)
	case api.ActionLogout:
		res = s.logoutUser(req)
	case api.ActionModData:
		res = s.modData(req)
	case api.ActionGetID:
		res = s.getId(req)
	case api.ActionDelData:
		res = s.delData(req)
	default:
		res = api.Response{Success: false, Message: "Acción desconocida"}
	}

	// Enviamos la respuesta en formato JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// generateSecureToken genera un token aleatorio seguro y establece su tiempo de expiración
func (s *server) generateSecureToken() (TokenInfo, error) {
	// Tamaño del token en bytes (32 bytes = 256 bits)
	tokenSize := 32

	// Crear buffer para el token
	tokenBytes := make([]byte, tokenSize)

	// Llenar con bytes aleatorios criptográficamente seguros
	if _, err := rand.Read(tokenBytes); err != nil {
		return TokenInfo{}, fmt.Errorf("error al generar token: %v", err)
	}

	// Codificar en base64 para hacerlo legible
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Establecer tiempo de expiración (24 horas desde ahora)
	expiresAt := time.Now().Add(500 * time.Millisecond)

	return TokenInfo{
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

// getTokenInfo obtiene la información completa del token (token + expiración)
func (s *server) getTokenInfo(username []byte) (TokenInfo, error) {
	// Obtener los datos del token desde la base de datos
	tokenData, err := s.db.Get("sessions", username)
	if err != nil {
		return TokenInfo{}, err
	}

	// Decodificar los datos del token
	var tokenInfo TokenInfo
	if err := json.Unmarshal(tokenData, &tokenInfo); err != nil {
		return TokenInfo{}, err
	}

	return tokenInfo, nil
}

// isTokenValid verifica si el token existe y no ha expirado
func (s *server) isTokenValid(username []byte, token string) bool {
	tokenInfo, err := s.getTokenInfo(username)
	if err != nil {
		return false
	}

	// Verificar que el token coincida y no haya expirado
	return tokenInfo.Token == token && time.Now().Before(tokenInfo.ExpiresAt)
}

// encrypt cifra los datos utilizando AES en modo CTR.
func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error al crear cipher: %v", err)
	}

	// Generar IV determinístico basado en el username
	iv := make([]byte, aes.BlockSize)
	hash := sha256.Sum256(plaintext)
	copy(iv, hash[:aes.BlockSize])

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	copy(ciphertext[:aes.BlockSize], iv)

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// decrypt descifra los datos utilizando AES en modo CTR.
func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Crear un nuevo buffer para el texto plano
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// registerUser registra un nuevo usuario, si no existe.
func (s *server) registerUser(req api.Request) api.Response {
	// Validación básica
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Verificamos si ya existe el usuario en 'auth'
	exists, err := s.userExists(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error al verificar usuario"}
	}
	if exists {
		return api.Response{Success: false, Message: "El usuario ya existe"}
	}

	// Generar un salt y hashear la contraseña
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return api.Response{Success: false, Message: "Error al hashear la contraseña"}
	}

	// Encriptar el nombre de usuario
	encryptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el nombre de usuario"}
	}

	// Almacenamos la contraseña hasheada en el namespace 'auth'
	if err := s.db.Put("auth", encryptedUsername, hashedPassword); err != nil {
		return api.Response{Success: false, Message: "Error al guardar credenciales"}
	}

	// Almacenamos la clave privada cifrada en el namespace 'prkey'
	if err := s.db.Put("prkey", encryptedUsername, []byte(req.PriKey)); err != nil {
		return api.Response{Success: false, Message: "Error al guardar clave privada"}
	}

	// Almacenamos la clave publica cifrada en el namespace 'pukey'
	if err := s.db.Put("pukey", encryptedUsername, []byte(req.PubKey)); err != nil {
		return api.Response{Success: false, Message: "Error al guardar clave publica"}
	}

	// Creamos una entrada vacía para los datos en 'userdata'
	var listData []string
	jListdata, err := json.Marshal(listData)
	if err != nil {
		return api.Response{Success: false, Message: "Error al crear list[]"}
	}
	encryptedList, err := encrypt(key, jListdata)
	if err := s.db.Put("userdata", encryptedUsername, encryptedList); err != nil {
		return api.Response{Success: false, Message: "Error al inicializar datos de usuario"}
	}

	return api.Response{Success: true, Message: "Usuario registrado"}
}

// loginUser valida credenciales en el namespace 'auth' y genera un token en 'sessions'.
func (s *server) loginUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Encriptar el nombre de usuario para buscar en la base de datos
	encryptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el nombre de usuario"}
	}

	// Recogemos la contraseña hasheada guardada en 'auth'
	hashedPassword, err := s.db.Get("auth", encryptedUsername)
	if err != nil {
		return api.Response{Success: false, Message: "Usuario no encontrado"}
	}

	// Comparamos la contraseña proporcionada con la contraseña hasheada
	if err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(req.Password)); err != nil {
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}

	// Generamos un nuevo token seguro con expiración
	tokenInfo, err := s.generateSecureToken()
	if err != nil {
		return api.Response{Success: false, Message: "Error al generar token de sesión"}
	}

	// Convertir tokenInfo a JSON para almacenar
	tokenData, err := json.Marshal(tokenInfo)
	if err != nil {
		return api.Response{Success: false, Message: "Error al preparar token para almacenamiento"}
	}

	// Guardamos el token y su información de expiración en 'sessions'
	if err := s.db.Put("sessions", encryptedUsername, tokenData); err != nil {
		return api.Response{Success: false, Message: "Error al crear sesión"}
	}

	return api.Response{Success: true, Message: "Login exitoso", Token: tokenInfo.Token}
}

// fetchData verifica el token y retorna el contenido del namespace 'userdata'.
func (s *server) fetchData(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Encriptar el nombre de usuario para buscar en la base de datos
	encryptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el nombre de usuario"}
	}

	if !s.isTokenValid(encryptedUsername, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Obtenemos los datos asociados al usuario desde 'userdata'
	rawData, err := s.db.Get("userdata", encryptedUsername)
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener datos del usuario"}
	}

	if len(rawData) == 0 {
		return api.Response{Success: false, Message: "No hay datos para descifrar"}
	}

	// Desencriptar los datos del usuario
	jListData, err := decrypt(key, rawData)
	if err != nil {
		return api.Response{Success: false, Message: "Error al desencriptar los datos del usuario"}
	}

	// Convertimos a lista string
	var listData []string
	json.Unmarshal(jListData, &listData)
	// Si no hay elementos
	if len(listData) == 0 {
		return api.Response{
			Success: false,
			Message: "No hay datos disponibles",
		}
	}

	return api.Response{
		Success: true,
		Message: "Datos privados de " + req.Username,
		Data:    listData,
	}
}

// updateData cambia el contenido de 'userdata' (los "datos" del usuario)
// después de validar el token.
func (s *server) updateData(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Encriptar el nombre de usuario para buscar en la base de datos
	encryptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el nombre de usuario"}
	}

	if !s.isTokenValid(encryptedUsername, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Obtenemos los datos asociados al usuario desde 'userdata'
	rawData, err := s.db.Get("userdata", encryptedUsername)
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener datos del usuario"}
	}

	// Si no hay datos
	if len(rawData) < 1 {
		return api.Response{
			Success: false,
			Message: "No hay datos disponibles",
		}
	}

	// Desencriptar los datos del usuario
	jListData, err := decrypt(key, rawData)
	if err != nil {
		return api.Response{Success: false, Message: "Error al desencriptar los datos del usuario"}
	}

	// Convertimos a lista string
	var listData []string
	json.Unmarshal(jListData, &listData)

	// Añadimos elemento a la lista
	listData = append(listData, req.Data)

	// Encriptar los datos del usuario antes de almacenarlos
	jListdata, err := json.Marshal(listData)
	if err != nil {
		return api.Response{Success: false, Message: "Error al crear list[]"}
	}
	encryptedList, err := encrypt(key, jListdata)
	if err := s.db.Put("userdata", encryptedUsername, encryptedList); err != nil {
		return api.Response{Success: false, Message: "Error al inicializar datos de usuario"}
	}

	return api.Response{Success: true, Message: "Datos de usuario actualizados"}
}

// logoutUser borra la sesión en 'sessions', invalidando el token.
func (s *server) logoutUser(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Encriptar el nombre de usuario para buscar en la base de datos
	encryptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el nombre de usuario"}
	}

	if !s.isTokenValid(encryptedUsername, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Borramos la entrada en 'sessions'
	if err := s.db.Delete("sessions", encryptedUsername); err != nil {
		return api.Response{Success: false, Message: "Error al cerrar sesión"}
	}

	return api.Response{Success: true, Message: "Sesión cerrada correctamente"}
}

func (s *server) modData(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Encriptar el nombre de usuario para buscar en la base de datos
	encryptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el nombre de usuario"}
	}

	if !s.isTokenValid(encryptedUsername, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Obtenemos los datos asociados al usuario desde 'userdata'
	rawData, err := s.db.Get("userdata", encryptedUsername)
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener datos del usuario"}
	}

	// Si no hay datos
	if len(rawData) < 1 {
		return api.Response{
			Success: false,
			Message: "No hay datos disponibles",
		}
	}

	// Desencriptar los datos del usuario
	jListData, err := decrypt(key, rawData)
	if err != nil {
		return api.Response{Success: false, Message: "Error al desencriptar los datos del usuario"}
	}

	// Convertimos a lista string
	var listData []string
	json.Unmarshal(jListData, &listData)

	// Añadimos elemento a la lista
	listData[req.Position] = req.Data

	// Encriptar los datos del usuario antes de almacenarlos
	jListdata, err := json.Marshal(listData)
	if err != nil {
		return api.Response{Success: false, Message: "Error al crear list[]"}
	}
	encryptedList, err := encrypt(key, jListdata)
	if err := s.db.Put("userdata", encryptedUsername, encryptedList); err != nil {
		return api.Response{Success: false, Message: "Error al inicializar datos de usuario"}
	}

	return api.Response{Success: true, Message: "El expediente ha sido modificado con exito"}
}

func (s *server) delData(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Encriptar el nombre de usuario para buscar en la base de datos
	encryptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el nombre de usuario"}
	}

	if !s.isTokenValid(encryptedUsername, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Obtenemos los datos asociados al usuario desde 'userdata'
	rawData, err := s.db.Get("userdata", encryptedUsername)
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener datos del usuario"}
	}

	// Si no hay datos
	if len(rawData) < 1 {
		return api.Response{
			Success: false,
			Message: "No hay datos disponibles",
		}
	}

	// Desencriptar los datos del usuario
	jListData, err := decrypt(key, rawData)
	if err != nil {
		return api.Response{Success: false, Message: "Error al desencriptar los datos del usuario"}
	}

	// Convertimos a lista string
	var listData []string
	json.Unmarshal(jListData, &listData)

	// Añadimos elemento a la lista
	listData = append(listData[:req.Position], listData[req.Position+1:]...) //Puede que no funcione

	// Encriptar los datos del usuario antes de almacenarlos
	jListdata, err := json.Marshal(listData)
	if err != nil {
		return api.Response{Success: false, Message: "Error al crear list[]"}
	}
	encryptedList, err := encrypt(key, jListdata)
	if err := s.db.Put("userdata", encryptedUsername, encryptedList); err != nil {
		return api.Response{Success: false, Message: "Error al inicializar datos de usuario"}
	}

	return api.Response{Success: true, Message: "El expediente ha sido eliminado con exito"}
}

// userExists comprueba si existe un usuario con la clave 'username'
// en 'auth'. Si no se encuentra, retorna false.
func (s *server) userExists(username string) (bool, error) {
	encryptedUsername, err := encrypt(key, []byte(username))
	if err != nil {
		return false, err
	}

	_, err = s.db.Get("auth", encryptedUsername)
	if err != nil {
		// Si no existe namespace o la clave:
		if strings.Contains(err.Error(), "bucket no encontrado: auth") {
			return false, nil
		}
		if err.Error() == "clave no encontrada: "+string(encryptedUsername) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *server) getId(api.Request) api.Response {
	jID, err := s.db.Get("gInt", []byte("gInt"))
	if err != nil {
		jID, _ := json.Marshal(1)
		if err := s.db.Put("gInt", []byte("gInt"), jID); err != nil {
			fmt.Println("Error: ", err.Error())
			return api.Response{Success: false, ID: 0}
		} else {
			fmt.Println("Error: ", err.Error())
			return api.Response{Success: true, ID: 1}
		}
	}
	var Id int
	json.Unmarshal(jID, &Id)
	Id = Id + 1
	jID, _ = json.Marshal(Id)
	if err := s.db.Put("gInt", []byte("gInt"), jID); err != nil {
		fmt.Println("Error: ", err.Error())
		return api.Response{Success: false, ID: 0}
	}
	return api.Response{Success: true, ID: Id}
}
