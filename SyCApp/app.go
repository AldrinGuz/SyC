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
)

var c = &client{}

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

func (a *App) Loggin(name string, pass string) bool {
	if c.currentUser == "" {
		return c.loginUser(name, pass)
	}
	return false
}

func (a *App) Register(name string, pass string) bool {
	return c.registerUser(name, pass)
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

// client estructura interna no exportada que controla
// el estado de la sesión (usuario, token) y logger.
type client struct {
	currentUser string
	authToken   string //encriptar
}

// registerUser pide credenciales y las envía al servidor para un registro.
// Si el registro es exitoso, se intenta el login automático.
func (c *client) registerUser(user string, pass string) bool {
	fmt.Println("** Registro de usuario **")

	username := user
	password := pass

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte(password))
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

	// Enviamos la acción al servidor
	res := c.sendRequest(api.Request{
		Action:   api.ActionRegister,
		Username: username,
		Password: encode64(keyLogin),
		PubKey:   encode64(compress(pubJSON)),
		PriKey:   encode64(encrypt(compress(pkJSON), keyData)),
	})

	// Mostramos resultado
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, probamos loguear automáticamente.
	if res.Success {
		loginRes := c.sendRequest(api.Request{
			Action:   api.ActionLogin,
			Username: username,
			Password: encode64(keyLogin),
		})
		if loginRes.Success {
			c.currentUser = username
			c.authToken = loginRes.Token
			fmt.Println("Login automático exitoso. Token guardado.")
			return true
		} else {
			fmt.Println("No se ha podido hacer login automático:", loginRes.Message)
			return false
		}
	} else {
		return false
	}
}

// loginUser pide credenciales y realiza un login en el servidor.
func (c *client) loginUser(user string, pass string) bool {
	fmt.Println("** Inicio de sesión **")

	username := user
	password := pass

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte(password))
	keyLogin := keyClient[:32] // una mitad para el login (256 bits)

	res := c.sendRequest(api.Request{
		Action:   api.ActionLogin,
		Username: username,
		Password: encode64(keyLogin),
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si login fue exitoso, guardamos currentUser y el token.
	if res.Success {
		c.currentUser = username
		c.authToken = res.Token
		fmt.Println("Sesión iniciada con éxito. Token guardado.")
		return true
	} else {
		return false
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
		Action:   api.ActionFetchData,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, mostramos la data recibida
	if res.Success {
		// Recibimos la lista de datos
		dataList := res.Data
		// Creamos lista vacia
		var desencriptedList []api.ClinicData
		for i, data := range dataList {
			// Convertimos a []byte
			encryptedData := decode64(data)

			// Desencriptamos
			key := []byte("B36712BF5659B9D42BB274C56F637B32") // Debes usar la misma clave para la encriptacion
			jData := decrypt(encryptedData, key)

			// Convertimos a struct
			var clinicData api.ClinicData
			json.Unmarshal(jData, &clinicData)

			fmt.Println("Datos paciente: ", i+1)            //1-
			fmt.Println("Nombre: ", clinicData.Name)        //4-
			fmt.Println("Apellidos: ", clinicData.SureName) //5-
			fmt.Println("ID: ", clinicData.ID)              //3-
			fmt.Println("N_Exp: ", clinicData.NumHisClin)   //2-
			fmt.Println("Edad: ", clinicData.Edad)          //6-
			fmt.Println("Sexo: ", clinicData.Sexo)          //7-
			fmt.Println("Estado civil: ", clinicData.EstadoCivil)
			fmt.Println("Ocupación: ", clinicData.Ocupacion)
			fmt.Println("Procedencia: ", clinicData.Procedencia)
			fmt.Println("Motivo: ", clinicData.Motivo)         //8
			fmt.Println("Enfermedad: ", clinicData.Enfermedad) //9

			// Añadimos el elemento a la lista
			desencriptedList = append(desencriptedList, clinicData)
		}
		jData, err := json.Marshal(desencriptedList)
		if err != nil {
			return "/Error: Fallo en la conversión de datos"
		}
		return string(jData)
	} else {
		return "/Error: 503 Service Unavailable*"
	}
}

// updateData pide nuevo texto y lo envía al servidor con ActionUpdateData.
func (c *client) updateData(datos string) bool {
	fmt.Println("** Actualizar datos del usuario **")

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

	// Convertimos a JSON
	jData, err := json.Marshal(newData)
	if err != nil {
		fmt.Println("Error en Marshal")
		return false
	}

	// Encryptamos
	key := []byte("B36712BF5659B9D42BB274C56F637B32") // Debes usar la misma clave para la desencriptacion
	encriptedData := encrypt(jData, key)

	// Conversion a string
	data := encode64(encriptedData)

	// Enviamos la solicitud de actualización
	res := c.sendRequest(api.Request{
		Action:   api.ActionUpdateData,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     data,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	if res.Success {
		fmt.Println("Datos enviados:", data)
		return true
	} else {
		return false
	}
}

// logoutUser llama a la acción logout en el servidor, y si es exitosa,
// borra la sesión local (currentUser/authToken).
func (c *client) logoutUser() bool {
	fmt.Println("** Cerrar sesión **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado.")
		return false
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
	if res.Success {
		c.currentUser = ""
		c.authToken = ""
		return true
	} else {
		return false
	}
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
