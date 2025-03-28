// El paquete server contiene el código del servidor.
// Interactúa con el cliente mediante una API JSON/HTTP
package server

import (
	"SyC/pkg/api"
	"SyC/pkg/store"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/bcrypt"
)

// server encapsula el estado de nuestro servidor
type server struct {
	db           store.Store // base de datos
	log          *log.Logger // logger para mensajes de error e información
	tokenCounter int64       // contador para generar tokens
}

// Run inicia la base de datos y arranca el servidor HTTP.
func Run() error {
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
	err = http.ListenAndServeTLS(":8080", "pkg/server/cert.pem", "pkg/server/key.pem", mux) // Modificar para que se levante con HTTPS

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
	default:
		res = api.Response{Success: false, Message: "Acción desconocida"}
	}

	// Enviamos la respuesta en formato JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// generateToken crea un token único incrementando un contador interno (inseguro)
func (s *server) generateToken() string {
	id := atomic.AddInt64(&s.tokenCounter, 1) // atomic es necesario al haber paralelismo en las peticiones HTTP.//Texto suficientemente largo tiene que tener una fecha de caducidad, para ello guardamos la fecha en la que se guarda el token
	return fmt.Sprintf("token_%d", id)        //Cada vez que hace una accion tiene que comprovar el token del cliente si no lo tiene tiene que mandar un mensaje de error
	//Se valida comprovando que es el mismo token y que esta dentro del tiempo limite
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

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
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
	key := []byte("B36712BF5659B9D42BB274C56F637B32") // Debes usar una clave segura de 32 bytes
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
	if err := s.db.Put("userdata", encryptedUsername, []byte("")); err != nil {
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
	key := []byte("B36712BF5659B9D42BB274C56F637B32") // Debes usar la misma clave que en el registro
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

	// Generamos un nuevo token, lo guardamos en 'sessions'
	token := s.generateToken()
	if err := s.db.Put("sessions", encryptedUsername, []byte(token)); err != nil {
		return api.Response{Success: false, Message: "Error al crear sesión"}
	}

	return api.Response{Success: true, Message: "Login exitoso", Token: token}
}

// fetchData verifica el token y retorna el contenido del namespace 'userdata'.
func (s *server) fetchData(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Encriptar el nombre de usuario para buscar en la base de datos
	key := []byte("B36712BF5659B9D42BB274C56F637B32") // Debes usar la misma clave que en el registro
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
	if string(rawData) == "" {
		return api.Response{
			Success: false,
			Message: "No hay datos disponibles",
		}
	}

	// Desencriptar los datos del usuario
	decryptedData, err := decrypt(key, rawData)
	if err != nil {
		return api.Response{Success: false, Message: "Error al desencriptar los datos del usuario"}
	}

	// Transformamos los datos
	var sData api.ClinicData
	err = json.Unmarshal(decryptedData, &sData)
	if err != nil {
		return api.Response{Success: false, Message: "Error " + err.Error()}
	}

	return api.Response{
		Success: true,
		Message: "Datos privados de " + req.Username,
		Data:    sData,
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
	key := []byte("B36712BF5659B9D42BB274C56F637B32") // Debes usar la misma clave que en el registro
	encryptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el nombre de usuario"}
	}

	if !s.isTokenValid(encryptedUsername, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Encriptar los datos del usuario antes de almacenarlos
	jData, err := json.Marshal(req.Data)
	if err != nil {
		return api.Response{Success: false, Message: "Error codificar struct to byte"}
	}
	encryptedData, err := encrypt(key, []byte(jData))
	if err != nil {
		return api.Response{Success: false, Message: "Error al encriptar los datos del usuario"}
	}

	// Escribimos el nuevo dato en 'userdata'
	if err := s.db.Put("userdata", encryptedUsername, encryptedData); err != nil {
		return api.Response{Success: false, Message: "Error al actualizar datos del usuario"}
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
	key := []byte("B36712BF5659B9D42BB274C56F637B32") // Debes usar la misma clave que en el registro
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

// userExists comprueba si existe un usuario con la clave 'username'
// en 'auth'. Si no se encuentra, retorna false.
func (s *server) userExists(username string) (bool, error) {
	key := []byte("B36712BF5659B9D42BB274C56F637B32") // Debes usar la misma clave que en el registro
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

// isTokenValid comprueba que el token almacenado en 'sessions'
// coincida con el token proporcionado.
func (s *server) isTokenValid(username []byte, token string) bool {
	storedToken, err := s.db.Get("sessions", username)
	if err != nil {
		return false
	}
	return string(storedToken) == token
}

func main() {
	if err := Run(); err != nil {
		log.Fatalf("Error al iniciar el servidor: %v", err)
	}
}
