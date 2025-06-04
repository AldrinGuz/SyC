// server.go
package server

import (
	"SyC/pkg/api"
	"SyC/pkg/store"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type server struct {
	db         store.Store
	log        *log.Logger
	jwtSecret  []byte
	tokenExp   time.Duration
	totpIssuer string
}

type JWTClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

var key []byte

func Run(n1 string) error {
	hash := sha256.Sum256([]byte(n1))
	key = hash[:24]

	jwtSecret := hash[:32]
	tokenExp := 60 * time.Minute

	db, err := store.NewStore("bbolt", "data/server.db")
	if err != nil {
		return fmt.Errorf("error abriendo base de datos: %v", err)
	}

	prueba, _ := db.Get("start", []byte("mk"))
	dec, _ := decrypt(key, prueba)
	if !bytes.Equal([]byte("KALI OSINT"), dec) {
		return fmt.Errorf("error la clave maestra no es coincidente")
	}

	srv := &server{
		db:         db,
		log:        log.New(os.Stdout, "[srv] ", log.LstdFlags),
		jwtSecret:  jwtSecret,
		tokenExp:   tokenExp,
		totpIssuer: "SyC App", //Nombre de la empresa
	}

	defer srv.db.Close()

	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	err = http.ListenAndServeTLS(":8080", "pkg/server/cert.pem", "pkg/server/key.pem", mux)
	return err
}

func (s *server) apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	var req api.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}

	var res api.Response
	switch req.Action {
	case api.ActionRegister:
		res = s.registerUser(req)
	case api.ActionLogin:
		res = s.loginUser(req)
	case api.ActionLogout:
		res = s.logoutUser(req)
	case api.ActionGetData:
		res = s.fetchData(req)
	case api.ActionPostData:
		res = s.addData(req)
	case api.ActionPutData:
		res = s.modData(req)
	case api.ActionDeleteData:
		res = s.delData(req)
	case api.ActionGetID:
		res = s.getId(req)
	case api.ActionEnable2FA:
		res = s.enable2FA(req)
	case api.ActionDisable2FA:
		res = s.disable2FA(req)
	default:
		res = api.Response{Success: false, Message: "Acción desconocida"}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (s *server) generateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(s.tokenExp)

	claims := &JWTClaims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "SyC Server",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func (s *server) validateJWT(tokenString string) (*JWTClaims, error) {
	claims := &JWTClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("método de firma inesperado: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("token inválido")
	}

	return claims, nil
}

func (s *server) isTokenValid(username, tokenString string) bool {
	claims, err := s.validateJWT(tokenString)
	if err != nil {
		s.log.Printf("Error validando token: %v", err)
		return false
	}

	return claims.Username == username
}

func (s *server) generateTOTPSecret(username string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      s.totpIssuer, //Nombre de la empresa generadora de totp
		AccountName: username,
		Period:      30,                //Tiemppo estimado para la caducidad del código
		Digits:      otp.DigitsSix,     //Número de dígitos que utilizara el código de tiempo
		Algorithm:   otp.AlgorithmSHA1, //Algoritmo de cifrado que usara junto con Hash-based Message Authentication Code para generar contraseñas de un solo uso basadas en el tiempo
	})
}

func (s *server) validateTOTP(username, code string) (bool, error) {
	encryptedUsername, err := encrypt(key, []byte(username))
	if err != nil {
		s.log.Printf("Error cifrando username: %v", err)
		return false, err
	}

	encryptedSecret, err := s.db.Get("totp_secrets", encryptedUsername)
	if err != nil {
		s.log.Printf("Error obteniendo secreto TOTP: %v", err)
		return false, err
	}

	secret, err := decrypt(key, encryptedSecret)
	if err != nil {
		s.log.Printf("Error descifrando secreto: %v", err)
		return false, err
	}
	//currentCode, _ := totp.GenerateCode(string(secret), time.Now())
	//s.log.Printf("Se esperaba %v", currentCode) ACTIVADO SOLO COMO COMPROBACION
	valid, err := totp.ValidateCustom(
		code,
		string(secret),
		time.Now(),
		totp.ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)

	if err != nil {
		s.log.Printf("Error validando código TOTP: %v", err)
		return false, err
	}

	return valid, nil
}

func (s *server) getTOTPQRCode(key *otp.Key) ([]byte, error) {
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return nil, err
	}

	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error al crear cipher: %v", err)
	}

	iv := make([]byte, aes.BlockSize)
	hash := sha256.Sum256(plaintext)
	copy(iv, hash[:aes.BlockSize])

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	copy(ciphertext[:aes.BlockSize], iv)

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

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

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func (s *server) registerUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	exists, err := s.userExists(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error al verificar usuario"}
	}
	if exists {
		return api.Response{Success: false, Message: "El usuario ya existe"}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return api.Response{Success: false, Message: "Error al hashear la contraseña"}
	}

	encryptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el nombre de usuario"}
	}

	rol, err := s.createRol(req.SIP, encryptedUsername)
	if err != nil {
		return api.Response{Success: false, Message: "Error al guardar rol " + err.Error()}
	}
	s.log.Println("El rol asignado es " + rol.Name)

	if err := s.db.Put("auth", encryptedUsername, hashedPassword); err != nil {
		return api.Response{Success: false, Message: "Error al guardar credenciales"}
	}

	if err := s.db.Put("prkey", encryptedUsername, []byte(req.PriKey)); err != nil {
		return api.Response{Success: false, Message: "Error al guardar clave privada"}
	}

	if err := s.db.Put("pukey", encryptedUsername, []byte(req.PubKey)); err != nil {
		return api.Response{Success: false, Message: "Error al guardar clave publica"}
	}

	var listData []string
	jListdata, err := json.Marshal(listData)
	if err != nil {
		return api.Response{Success: false, Message: "Error al crear list[]"}
	}
	encryptedList, err := encrypt(key, jListdata)
	if err := s.db.Put("userkeys", encryptedUsername, encryptedList); err != nil {
		return api.Response{Success: false, Message: "Error al añadir las keys de usuario"}
	}
	var otherList [][]string
	jListdata, err = json.Marshal(otherList)
	if err != nil {
		return api.Response{Success: false, Message: "Error al crear list[]"}
	}
	encryptedList, _ = encrypt(key, jListdata)
	if err := s.db.Put("userdata", encryptedUsername, encryptedList); err != nil {
		return api.Response{Success: false, Message: "Error al inicializar datos de usuario"}
	}

	totpSecret, err := s.generateTOTPSecret(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error al generar secreto 2FA"}
	}

	encryptedSecret, err := encrypt(key, []byte(totpSecret.Secret()))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar secreto 2FA"}
	}

	if err := s.db.Put("totp_secrets", encryptedUsername, encryptedSecret); err != nil {
		return api.Response{Success: false, Message: "Error al guardar secreto 2FA"}
	}

	qrCode, err := s.getTOTPQRCode(totpSecret)
	if err != nil {
		return api.Response{Success: false, Message: "Error al generar QR code 2FA"}
	}

	return api.Response{
		Success: true,
		Message: "Usuario registrado. Escanea el QR con tu app de autenticación",
		DataMap: map[string]interface{}{
			"qr_code": base64.StdEncoding.EncodeToString(qrCode),
			"secret":  totpSecret.Secret(),
		},
	}
}

func (s *server) loginUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	encryptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		s.log.Printf("Error cifrando username: %v", err)
		return api.Response{Success: false, Message: "Error al cifrar el nombre de usuario"}
	}

	hashedPassword, err := s.db.Get("auth", encryptedUsername)
	if err != nil {
		s.log.Printf("Error obteniendo hash de contraseña: %v", err)
		return api.Response{Success: false, Message: "Usuario no encontrado"}
	}

	if err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(req.Password)); err != nil {
		s.log.Printf("Error comparando contraseñas: %v", err)
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}

	encriptedId, err := s.db.Get("gInfo", encryptedUsername)
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener el userID en gInfo"}
	}
	byteUserID, err := decrypt(key, encriptedId)
	if err != nil {
		return api.Response{Success: false, Message: "Error al desencriptar el userID"}
	}

	_, err = s.db.Get("totp_secrets", encryptedUsername)
	if err != nil {
		s.log.Printf("2FA no configurado para el usuario, procediendo con login normal")
		tokenString, err := s.generateJWT(req.Username)
		if err != nil {
			s.log.Printf("Error generando token JWT: %v", err)
			return api.Response{Success: false, Message: "Error al generar token JWT"}
		}

		rol, err := s.userRol(encryptedUsername)
		if err != nil {
			return api.Response{Success: false, Message: "Error al obtener rol " + err.Error()}
		}

		return api.Response{
			Success: true,
			Message: "Login exitoso",
			Token:   tokenString,
			Rol:     rol,
			Keys:    []string{string(byteUserID)},
		}
	}

	if req.TOTPCode == "" {
		s.log.Printf("2FA requerido para el usuario %s", req.Username)
		return api.Response{
			Success:     true,
			Message:     "Por favor ingresa tu código de autenticación de dos factores",
			Requires2FA: true,
		}
	}

	valid, err := s.validateTOTP(req.Username, req.TOTPCode)
	if err != nil {
		s.log.Printf("Error validando código 2FA: %v", err)
		return api.Response{Success: false, Message: "Error validando código de autenticación"}
	}
	if !valid {
		return api.Response{Success: false, Message: "Código de autenticación inválido"}
	}

	tokenString, err := s.generateJWT(req.Username)
	if err != nil {
		s.log.Printf("Error generando token JWT: %v", err)
		return api.Response{Success: false, Message: "Error al generar token JWT"}
	}

	rol, err := s.userRol(encryptedUsername)
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener rol " + err.Error()}
	}

	return api.Response{
		Success: true,
		Message: "Login exitoso con autenticación en dos factores",
		Token:   tokenString,
		Rol:     rol,
		Keys:    []string{string(byteUserID)},
	}
}

func (s *server) enable2FA(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	encryptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar nombre de usuario"}
	}

	rol, err := s.userRol(encryptedUsername)
	if err != nil || rol.Level < 2 {
		return api.Response{Success: false, Message: "No tienes los permisos necesarios"}
	}

	// Generar nuevo secreto TOTP
	totpSecret, err := s.generateTOTPSecret(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error al generar secreto 2FA"}
	}

	// Guardar el secreto cifrado
	encryptedSecret, err := encrypt(key, []byte(totpSecret.Secret()))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar secreto 2FA"}
	}

	if err := s.db.Put("totp_secrets", encryptedUsername, encryptedSecret); err != nil {
		return api.Response{Success: false, Message: "Error al guardar secreto 2FA"}
	}

	// Generar QR code
	qrCode, err := s.getTOTPQRCode(totpSecret)
	if err != nil {
		return api.Response{Success: false, Message: "Error al generar QR code 2FA"}
	}

	return api.Response{
		Success: true,
		Message: "2FA habilitado. Escanea el QR con tu app de autenticación",
		DataMap: map[string]interface{}{
			"qr_code": base64.StdEncoding.EncodeToString(qrCode),
			"secret":  totpSecret.Secret(),
		},
	}
}

func (s *server) disable2FA(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	encryptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar nombre de usuario"}
	}

	rol, err := s.userRol(encryptedUsername)
	if err != nil || rol.Level < 2 {
		return api.Response{Success: false, Message: "No tienes los permisos necesarios"}
	}

	if err := s.db.Delete("totp_secrets", encryptedUsername); err != nil {
		return api.Response{Success: false, Message: "Error al deshabilitar 2FA"}
	}

	return api.Response{Success: true, Message: "Autenticación en dos factores deshabilitada"}
}

// fetchData verifica el token y retorna el contenido del namespace 'userdata'.
func (s *server) fetchData(req api.Request) api.Response {
	var sendData []string
	var listKeys []string
	var listData [][]string
	var res api.Response

	encriptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al encriptar el username"}
	}
	rol, err := s.userRol(encriptedUsername)
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener el rol del usuario"}
	}
	if rol.Level == 1 {
		encriptedId, err := s.db.Get("gInfo", encriptedUsername)
		if err != nil {
			return api.Response{Success: false, Message: "Error al obtener el userID en gInfo"}
		}
		byteUserID, err := decrypt(key, encriptedId)
		if err != nil {
			return api.Response{Success: false, Message: "Error al desencriptar el userID"}
		}
		fullhash, err := base64.StdEncoding.DecodeString(string(byteUserID)) // el fullhash es el correcto
		if err != nil {
			return api.Response{Success: false, Message: "Error al obtener la key de user"}
		}
		listDoctor, err := s.db.ListKeys("auth")
		if err != nil {
			return api.Response{Success: false, Message: "Error al obtener la lista de médicos"}
		}
		var listOfUserdata [][]string
		for _, doctor := range listDoctor { // Recorre la lista con []byte que son los username encriptados
			list, _ := s.db.Get("userdata", doctor)    // Los utiliza para buscar en userdata devuelve un []byte
			jListData, _ := decrypt(key, list)         // []byte son los datos que al desencriptar []byte
			json.Unmarshal(jListData, &listOfUserdata) // []byte hay que transformarlo en [][]string
			for _, data := range listOfUserdata {      // de la lista buscamos de cada []string el primer elemento
				encriptedIdent, _ := base64.StdEncoding.DecodeString(data[0])
				byteIdent := comprobador(encriptedIdent, fullhash[:32])
				if string(byteIdent) == "user" {
					sendData = append(sendData, data[1])
				}
			}
		}
	} else {
		listData, listKeys, res = s.writeUserData(req, 1)
		if !res.Success {
			return res
		}
		for _, data := range listData {
			sendData = append(sendData, data[1])
		}
	}

	return api.Response{
		Success: true,
		Message: "Datos privados de " + req.Username,
		Data:    sendData,
		Keys:    listKeys,
	}
}

// addData cambia el contenido de 'userdata' (los "datos" del usuario)
// después de validar el token.
func (s *server) addData(req api.Request) api.Response {
	listData, listKeys, res := s.writeUserData(req, 2)
	if !res.Success {
		return res
	}

	// Añadimos elemento a la lista
	listData = append(listData, req.Data)
	listKeys = append(listKeys, req.PriKey)

	return s.closeUserData(listData, listKeys, req, "Datos de usuario actualizados")
}

// logoutUser invalida el token (en el cliente)
func (s *server) logoutUser(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	return api.Response{Success: true, Message: "Sesión cerrada correctamente"}
}

func (s *server) modData(req api.Request) api.Response {
	listData, listKeys, res := s.writeUserData(req, 2)
	if !res.Success {
		return res
	}
	// Añadimos elemento a la lista
	listData[req.Position] = req.Data
	listKeys[req.Position] = req.PriKey

	return s.closeUserData(listData, listKeys, req, "El expediente ha sido modificado con exito")
}

func (s *server) delData(req api.Request) api.Response {
	listData, listKeys, res := s.writeUserData(req, 2)
	if !res.Success {
		return res
	}

	// Añadimos elemento a la lista
	listData = append(listData[:req.Position], listData[req.Position+1:]...)
	listKeys = append(listKeys[:req.Position], listKeys[req.Position+1:]...)

	return s.closeUserData(listData, listKeys, req, "El expediente ha sido eliminado con exito")
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

// Crea el rol en funcion del sip, el administrador puede modificar el nivel y la autorización
func (s *server) createRol(userid string, encryptedUsername []byte) (api.Rol, error) {
	var rol api.Rol
	// Encripta la cadena con la key del servidor
	encryptedUserid, err := encrypt(key, []byte(userid))
	if err != nil {
		return rol, err
	}
	// Hace una llamada a db
	userRol, err := s.db.Get("rol", encryptedUserid)
	if err != nil {
		// Si no exite la carpeta rol o no tiene registrado el sip doblemente encriptado crea un rol por defecto para el sip
		if strings.Contains(err.Error(), "bucket no encontrado: rol") || err.Error() == "clave no encontrada: "+string(encryptedUserid) {
			rol.Name = "doctor"
			rol.Level = 2
			jRol, err := json.Marshal(rol)
			if err != nil {
				return api.Rol{}, err
			}
			err = s.db.Put("rol", encryptedUserid, jRol) // Añade el sip y el rol en la carpeta rol
			if err != nil {
				return api.Rol{}, err
			}
			err = s.db.Put("gInfo", encryptedUsername, encryptedUserid) // Añade el usuario a sociado a el sip en la carpeta gInfo
			if err != nil {
				return api.Rol{}, err
			}
			return rol, nil
		}
		return rol, err
	}
	// Si encuentra un rol asignado al sip devuelve el rol y asigna el usuario al sip
	err = json.Unmarshal(userRol, &rol)
	if err != nil {
		return api.Rol{}, err
	}
	err = s.db.Put("gInfo", encryptedUsername, encryptedUserid) // Añade el usuario a sociado a el sip en la carpeta gInfo
	if err != nil {
		return api.Rol{}, err
	}
	return rol, nil
}

// Obtiene el rol del usuario segun el sip asociado a el
func (s *server) userRol(encryptedUsername []byte) (api.Rol, error) {
	var rol api.Rol
	encryptedUserid, err := s.db.Get("gInfo", encryptedUsername) // Obtiene el sip doblemente encriptado
	if err != nil {
		return rol, err
	}
	jRol, err := s.db.Get("rol", encryptedUserid) // Obtiene el rol
	if err != nil {
		return rol, err
	}
	err = json.Unmarshal(jRol, &rol) // Lo transforma nuevamente a struct
	if err != nil {
		return api.Rol{}, err
	}
	return rol, nil
}

func (s *server) getId(api.Request) api.Response {
	max := new(big.Int).Lsh(big.NewInt(1), 24)
	n, _ := rand.Int(rand.Reader, max)
	return api.Response{Success: true, ID: int(n.Int64())}
}

func (s *server) writeUserData(req api.Request, accessLevel int) ([][]string, []string, api.Response) {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return nil, nil, api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Encriptar el nombre de usuario para buscar en la base de datos
	encryptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		return nil, nil, api.Response{Success: false, Message: "Error al cifrar el nombre de usuario"}
	}

	if !s.isTokenValid(req.Username, req.Token) {
		return nil, nil, api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	rol, err := s.userRol(encryptedUsername)
	if err != nil || rol.Level < accessLevel {
		return nil, nil, api.Response{Success: false, Message: "No tienes los permisos necesarios"}
	}

	// Obtenemos los datos asociados al usuario desde 'userdata'
	rawData, err := s.db.Get("userdata", encryptedUsername)
	if err != nil {
		return nil, nil, api.Response{Success: false, Message: "Error al obtener datos del usuario 3"}
	}

	// Si no hay datos
	if len(rawData) < 1 {
		return nil, nil, api.Response{Success: false, Message: "No hay datos disponibles"}
	}

	// Desencriptar los datos del usuario
	jListData, err := decrypt(key, rawData)
	if err != nil {
		return nil, nil, api.Response{Success: false, Message: "Error al desencriptar los datos del usuario"}
	}

	// Convertimos a lista string
	var listData [][]string
	json.Unmarshal(jListData, &listData)

	listkeys, res := s.writeUserK(req)
	if !res.Success {
		return nil, nil, res
	}

	return listData, listkeys, api.Response{Success: true}
}

func (s *server) writeUserK(req api.Request) ([]string, api.Response) {
	// Encriptar el nombre de usuario para buscar en la base de datos
	encryptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		return nil, api.Response{Success: false, Message: "Error al cifrar el nombre de usuario"}
	}

	// Obtenemos los datos asociados al usuario desde 'userdata'
	rawKeys, err := s.db.Get("userkeys", encryptedUsername)
	if err != nil {
		return nil, api.Response{Success: false, Message: "Error al obtener datos del usuario 4"}
	}

	// Si no hay datos
	if len(rawKeys) < 1 {
		return nil, api.Response{Success: false, Message: "No hay datos disponibles"}
	}

	// Desencriptar los datos del usuario
	jListKeys, err := decrypt(key, rawKeys)
	if err != nil {
		return nil, api.Response{Success: false, Message: "Error al desencriptar los datos del usuario"}
	}

	// Convertimos a lista string
	var listKeys []string
	json.Unmarshal(jListKeys, &listKeys)

	return listKeys, api.Response{Success: true}
}

func (s *server) closeUserData(listData [][]string, listKeys []string, req api.Request, message string) api.Response {
	// Encriptar el nombre de usuario para buscar en la base de datos
	encryptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el nombre de usuario"}
	}

	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}
	// Encriptar los datos del usuario antes de almacenarlos
	jListdata, err := json.Marshal(listData)
	if err != nil {
		return api.Response{Success: false, Message: "Error al crear list[]"}
	}
	encryptedList, err := encrypt(key, jListdata)
	if err := s.db.Put("userdata", encryptedUsername, encryptedList); err != nil {
		return api.Response{Success: false, Message: "Error al inicializar datos de usuario"}
	}
	return s.closeUserK(listKeys, req, message)
}
func (s *server) closeUserK(listKeys []string, req api.Request, message string) api.Response {
	// Encriptar el nombre de usuario para buscar en la base de datos
	encryptedUsername, err := encrypt(key, []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el nombre de usuario"}
	}

	// Encriptar los datos del usuario antes de almacenarlos
	jListdata, err := json.Marshal(listKeys)
	if err != nil {
		return api.Response{Success: false, Message: "Error al crear list[]"}
	}
	encryptedList, err := encrypt(key, jListdata)
	if err := s.db.Put("userkeys", encryptedUsername, encryptedList); err != nil {
		return api.Response{Success: false, Message: "Error al añadir las keys de usuario"}
	}
	return api.Response{Success: true, Message: message}
}

// función para cifrar (con AES en este caso), adjunta el IV al principio
func comprobador(data, key []byte) (out []byte) {
	if len(data) < 16 {
		return
	}
	out = make([]byte, len(data)-16) // la salida no va a tener el IV
	blk, err := aes.NewCipher(key)   // cifrador en bloque (AES), usa key
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out, data[16:])     // desciframos (doble cifrado) los datos
	return
}
