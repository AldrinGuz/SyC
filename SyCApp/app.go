package main

import (
	"SyCApp/backend/api"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

var c = &client{}

// key compuesto por los credenciales de user
var key []byte

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) Loggin(name, pass string) string {
	if c.currentUser == "" {
		_, mess := c.loginUser(name, pass)
		return mess
	}
	return ""
}

func (a *App) Register(name, pass string, sip int) string {
	return c.registerUser(name, pass, sip)
}

func (a *App) Auth2FA(name, pass, code string) string {
	return c.auth2FA(name, pass, code)
}

func (a *App) Manage2FA(shutdown bool) string {
	return c.manage2FA(shutdown)
}

func (a *App) Logout() bool {
	return c.logoutUser()
}

func (a *App) UpdateData(data string) bool {
	return c.updateData(data)
}

func (a *App) GetData() string {
	return c.fetchData()
}

func (a *App) ModData(data string, id int) bool {
	return c.modData(data, id)
}

func (a *App) DelData(ID int) bool {
	return c.delData(ID)
}

// client estructura interna no exportada que controla
// el estado de la sesión (usuario, token) y logger.
type client struct {
	currentUser string
	authToken   string
	rol         api.Rol
	keys        []string
}

// registerUser pide credenciales y las envía al servidor para un registro.
// Si el registro es exitoso, se intenta el login automático.
func (c *client) registerUser(user string, pass string, sip int) string {
	fmt.Println("** Registro de usuario **")

	username := user
	password := pass
	SIP := sip

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte(password + username))
	keyLogin := keyClient[:32]  // una mitad para el login (256 bits)
	keyData := keyClient[32:64] // la otra para los datos (256 bits)

	// generamos un par de claves (privada, pública) para el servidor
	pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	chk(err)
	pkClient.Precompute() // aceleramos su uso con un precálculo

	pkJSON, err := json.Marshal(&pkClient) // codificamos con JSON
	chk(err)

	keyPub := pkClient.Public()           // extraemos la clave pública por separado
	pubJSON, err := json.Marshal(&keyPub) // y codificamos con JSON
	chk(err)

	hashSIP := sha512.Sum512([]byte(strconv.Itoa(SIP))) // Datos en bruto se reconvierten con string()

	// Enviamos la acción al servidor
	res := c.sendRequest(api.Request{
		Action:   api.ActionRegister,
		Username: username,
		Password: encode64(keyLogin),
		PubKey:   encode64(compress(pubJSON)),
		PriKey:   encode64(encrypt(compress(pkJSON), keyData)),
		SIP:      encode64(hashSIP[:]),
	})

	// Mostramos resultado
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, probamos loguear automáticamente.
	if res.Success {
		// Mostrar QR code y secreto para 2FA (usando DataMap)
		if res.DataMap != nil {
			if qrCode, ok := res.DataMap["qr_code"].(string); ok {
				fmt.Println("\nEscanea este código QR con tu app de autenticación:")
				return qrCode
			}
			if secret, ok := res.DataMap["secret"].(string); ok {
				fmt.Println("\nO ingresa este código manualmente:", secret)
			}
		}
	}
	return ""
}

// loginUser pide credenciales y realiza un login en el servidor.
func (c *client) loginUser(user, pass string) (bool, string) {
	fmt.Println("** Inicio de sesión **")

	username := user
	password := pass

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte(password + username))
	keyLogin := keyClient[:32] // una mitad para el login (256 bits)

	res := c.sendRequest(api.Request{
		Action:   api.ActionLogin,
		Username: username,
		Password: encode64(keyLogin),
	})

	if res.Requires2FA {
		fmt.Println("\nAutenticación en dos factores requerida")
		return true, "Requiere 2FA"
	}

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si login fue exitoso, guardamos currentUser y el token.
	if res.Success {
		fullHash := sha512.Sum512([]byte(password + username))
		key = fullHash[:24]
		c.currentUser = username
		c.authToken = res.Token
		c.rol = res.Rol
		c.keys = res.Keys
		fmt.Println("Sesión iniciada con éxito. Token guardado. Rol asignado con exito " + res.Rol.Name)
		return true, "Autorizado: " + res.Rol.Name
	} else {
		return false, res.Message
	}
}

func (c *client) auth2FA(user, pass, code string) string {
	keyClient := sha512.Sum512([]byte(pass + user))
	keyLogin := keyClient[:32]

	res := c.sendRequest(api.Request{
		Action:   api.ActionLogin,
		Username: user,
		Password: encode64(keyLogin),
		TOTPCode: code,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	if res.Success {
		key = keyLogin
		c.currentUser = user
		c.authToken = res.Token
		c.rol = res.Rol
		c.keys = res.Keys
		return "Autorizado: " + res.Rol.Name
	}
	return ""
}

func (c *client) manage2FA(shutdown bool) string {
	if !shutdown {
		res := c.sendRequest(api.Request{
			Action:   api.ActionDisable2FA,
			Username: c.currentUser,
			Token:    c.authToken,
		})

		fmt.Println("Éxito:", res.Success)
		fmt.Println("Mensaje:", res.Message)
		return "Autenticación en Dos Factores deshabilitada"

	} else {
		res := c.sendRequest(api.Request{
			Action:   api.ActionEnable2FA,
			Username: c.currentUser,
			Token:    c.authToken,
		})

		fmt.Println("Éxito:", res.Success)
		fmt.Println("Mensaje:", res.Message)

		if res.Success {
			// Mostrar QR code y secreto para 2FA (usando DataMap)
			if res.DataMap != nil {
				if qrCode, ok := res.DataMap["qr_code"].(string); ok {
					fmt.Println("\nEscanea este código QR con tu app de autenticación:")
					return qrCode
				}
				if secret, ok := res.DataMap["secret"].(string); ok {
					fmt.Println("\nO ingresa este código manualmente:", secret)
				}
			}
		}
		return ""
	}
}

// fetchData pide datos privados al servidor.
// El servidor devuelve la data asociada al usuario logueado.
func (c *client) fetchData() string {
	fmt.Println("** Obtener datos del usuario **")

	// Chequeo básico de que haya sesión
	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return "/Error: 401 Unauthorized*"
	}

	// Hacemos la request con ActionFetchData
	res := c.sendRequest(api.Request{
		Action:   api.ActionGetData,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, mostramos la data recibida
	if res.Success {
		// Recibimos la lista de datos
		dataList := res.Data
		keyList := res.Keys
		// Creamos lista vacia
		var desencriptedList []api.ClinicData
		for i, data := range dataList {
			encryptedData := decode64(data)
			var fullhash []byte
			if c.rol.Name == "patient" {
				fullhash = decode64(c.keys[0])
			}
			if c.rol.Name == "doctor" {
				encryptedKey := decode64(keyList[i])
				fullhash = decrypt(encryptedKey, key)
			}
			compr := decrypt(encryptedData, fullhash[:32])
			jData := decompress(compr)

			var clinicData api.ClinicData
			json.Unmarshal(jData, &clinicData)

			// Añadimos el elemento a la lista
			desencriptedList = append(desencriptedList, clinicData)
		}
		jData, err := json.Marshal(desencriptedList)
		if err != nil {
			return "/Error: Fallo en la conversión de datos"
		}
		return string(jData)
	} else {
		c.currentUser = ""
		c.authToken = ""
		key = nil
		return "/Error: 503 Service Unavailable*"
	}
}

// updateData pide nuevo texto y lo envía al servidor con ActionUpdateData.
func (c *client) updateData(datos string) bool {
	fmt.Println("** Actualizar datos del usuario **")
	if c.rol.Name == "patient" {
		fmt.Println("No tienes acceso a esta función")
		return false
	}

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return false
	}

	// Leemos la nueva Data
	var newData api.ClinicData
	if json.Unmarshal([]byte(datos), &newData) != nil {
		fmt.Println("Ha habido un erro en la conversión")
		return false
	}

	//Pedimos id al servidor
	res1 := c.sendRequest(api.Request{
		Action:   api.ActionGetID,
		Username: c.currentUser,
		Token:    c.authToken,
	})
	if res1.Success {
		newData.ID = res1.ID
	} else {
		fmt.Println("Error al obtener ID")
		c.currentUser = ""
		c.authToken = ""
		key = nil
		return false
	}

	data, newKey := packData(newData)

	// Enviamos la solicitud de actualización
	res2 := c.sendRequest(api.Request{
		Action:   api.ActionPostData,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     data,
		PriKey:   newKey,
	})

	fmt.Println("Éxito:", res2.Success)
	fmt.Println("Mensaje:", res2.Message)

	if res2.Success {
		fmt.Println("Datos enviados:", data)
		return true
	} else {
		c.currentUser = ""
		c.authToken = ""
		key = nil
		return false
	}
}

func (c *client) modData(datos string, id int) bool {
	if c.rol.Name == "patient" {
		fmt.Println("No tienes acceso a esta función")
		return false
	}
	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return false
	}

	// Leemos la nueva Data
	var newData api.ClinicData
	if json.Unmarshal([]byte(datos), &newData) != nil {
		fmt.Println("Ha habido un erro en la conversión")
		return false
	}

	sendData, sendKey := packData(newData)

	// Hacemos la request con ActionFetchData
	res1 := c.sendRequest(api.Request{
		Action:   api.ActionGetData,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res1.Success)
	fmt.Println("Mensaje:", res1.Message)

	// Si fue exitoso, mostramos la data recibida
	if !res1.Success {
		return false
	}

	posicion, _ := unpackData(res1, id)
	if posicion == -1 {
		fmt.Println("El ID no se encuentra entre los expedientes admitidos")
		return false
	}

	res := c.sendRequest(api.Request{
		Action:   api.ActionPutData,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     sendData,
		Position: posicion,
		PriKey:   sendKey,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if !res.Success {
		c.currentUser = ""
		c.authToken = ""
		key = nil
		return false
	}
	return true
}

func (c *client) delData(ID int) bool {
	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return false
	}

	// Hacemos la request con ActionFetchData
	res1 := c.sendRequest(api.Request{
		Action:   api.ActionGetData,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res1.Success)
	fmt.Println("Mensaje:", res1.Message)

	// Si fue exitoso, mostramos la data recibida
	if !res1.Success {
		return false
	}

	posicion, _ := unpackData(res1, ID)
	if posicion == -1 {
		fmt.Println("El ID no se encuentra entre los expedientes admitidos")
		return false
	}

	// Enviamos la solicitud de actualización
	res := c.sendRequest(api.Request{
		Action:   api.ActionDeleteData,
		Username: c.currentUser,
		Token:    c.authToken,
		Position: posicion,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if !res.Success {
		c.currentUser = ""
		c.authToken = ""
		key = nil
		return false
	}
	return true
}

// logoutUser llama a la acción logout en el servidor, y si es exitosa,
// borra la sesión local (currentUser/authToken).
func (c *client) logoutUser() bool {
	fmt.Println("** Cerrar sesión **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado.")
	}

	// Llamamos al servidor con la acción ActionLogout
	res := c.sendRequest(api.Request{
		Action:   api.ActionLogout,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, limpiamos la sesión local.
	c.currentUser = ""
	c.authToken = ""
	key = nil
	return true
}

// sendRequest envía un POST JSON a la URL del servidor y
// devuelve la respuesta decodificada. Se usa para todas las acciones.
func (c *client) sendRequest(req api.Request) api.Response {
	jsonData, _ := json.Marshal(req)

	// Configurar transporte con TLS (permitiendo certificados autofirmados)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	// Usar el cliente con TLS
	resp, err := client.Post("https://localhost:8080/api", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error al contactar con el servidor:", err)
		return api.Response{Success: false, Message: "Error de conexión"}
	}
	defer resp.Body.Close()

	// Leemos el body de respuesta y lo desempaquetamos en un api.Response
	body, _ := io.ReadAll(resp.Body)
	var res api.Response
	_ = json.Unmarshal(body, &res)
	return res
}

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// función para cifrar (con AES en este caso), adjunta el IV al principio
func encrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reservamos espacio para el IV al principio
	rand.Read(out[:16])                 // generamos el IV
	blk, err := aes.NewCipher(key)      // cifrador en bloque (AES), usa key
	chk(err)                            // comprobamos el error
	ctr := cipher.NewCTR(blk, out[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)    // ciframos los datos
	return
}

// función para descifrar (con AES en este caso)
func decrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)     // la salida no va a tener el IV
	blk, err := aes.NewCipher(key)       // cifrador en bloque (AES), usa key
	chk(err)                             // comprobamos el error
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out, data[16:])     // desciframos (doble cifrado) los datos
	return
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

// función para comprimir
func compress(data []byte) []byte {
	var b bytes.Buffer      // b contendrá los datos comprimidos (tamaño variable)
	w := zlib.NewWriter(&b) // escritor que comprime sobre b
	w.Write(data)           // escribimos los datos
	w.Close()               // cerramos el escritor (buffering)
	return b.Bytes()        // devolvemos los datos comprimidos
}

func decompress(data []byte) []byte {
	var b bytes.Buffer // b contendrá los datos descomprimidos

	r, err := zlib.NewReader(bytes.NewReader(data)) // lector descomprime al leer

	chk(err)         // comprobamos el error
	io.Copy(&b, r)   // copiamos del descompresor (r) al buffer (b)
	r.Close()        // cerramos el lector (buffering)
	return b.Bytes() // devolvemos los datos descomprimidos
}

func packData(Data api.ClinicData) ([]string, string) {
	var sendData []string
	jData, err := json.Marshal(Data) // Convertimos a JSON
	if err != nil {
		fmt.Println("Error en Marshal 315")
		return nil, ""
	}
	compr := compress(jData) // Comprimimos
	fullhash := sha512.Sum512([]byte(strconv.Itoa(Data.SIP)))
	encriptedData := encrypt(compr, fullhash[:32])           // Encryptamos los datos
	encriptedIdent := encrypt([]byte("user"), fullhash[:32]) // Encryptamos los datos
	encriptedHash := encrypt(fullhash[:], key)               // Encryptamos el hash
	dataSend := encode64(encriptedData)                      // Conversion a string
	sendKey := encode64(encriptedHash)
	sendData = append(sendData, encode64(encriptedIdent), dataSend)
	return sendData, sendKey
}

func unpackData(res api.Response, id int) (int, api.ClinicData) {
	posicion := -1
	// Recibimos la lista de datos
	for i, data := range res.Data {
		encryptedData := decode64(data) // Convertimos a []byte
		encryptedKey := decode64(res.Keys[i])
		fullhash := decrypt(encryptedKey, key)
		compr := decrypt(encryptedData, fullhash[:32]) // Desencriptamos
		jData := decompress(compr)                     // Descomprimimos
		var clinicData api.ClinicData                  // Convertimos a struct
		json.Unmarshal(jData, &clinicData)
		if id == clinicData.ID { // Condicion
			posicion = i
			return posicion, clinicData
		}
	}
	return posicion, api.ClinicData{}
}
