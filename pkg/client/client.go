// El paquete client contiene la lógica de interacción con el usuario
// así como de comunicación con el servidor.
package client

import (
	"SyC/pkg/api"
	"SyC/pkg/ui"
	"bytes"
	"compress/zlib"
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
	"log"
	"net/http"
	"os"
	"strconv"
)

// client estructura interna no exportada que controla
// el estado de la sesión (usuario, token) y logger.
type client struct {
	log         *log.Logger
	currentUser string
	authToken   string
}

// key compuesto por los credenciales de user
var key []byte

// Run es la única función exportada de este paquete.
// Crea un client interno y ejecuta el bucle principal.
func Run() {
	// Creamos un logger con prefijo 'cli' para identificar
	// los mensajes en la consola.
	c := &client{
		log: log.New(os.Stdout, "[cli] ", log.LstdFlags),
	}
	c.runLoop()
}

// runLoop maneja la lógica del menú principal.
// Si NO hay usuario logueado, se muestran ciertas opciones;
// si SÍ hay usuario logueado, se muestran otras.
func (c *client) runLoop() {
	for {
		ui.ClearScreen()

		// Construimos un título que muestre el usuario logueado, si lo hubiera.
		var title string
		if c.currentUser == "" {
			title = "Menú"
		} else {
			title = fmt.Sprintf("Menú (%s)", c.currentUser)
		}

		// Generamos las opciones dinámicamente, según si hay un login activo.
		var options []string
		if c.currentUser == "" {
			// Usuario NO logueado: Registro, Login, Salir
			options = []string{
				"Registrar usuario",
				"Iniciar sesión",
				"Salir",
			}
		} else {
			// Usuario logueado: Ver datos, Actualizar datos, Logout, Salir
			options = []string{
				"Ver datos",
				"Actualizar datos",
				"Cerrar sesión",
				"Salir",
			}
		}

		// Mostramos el menú y obtenemos la elección del usuario.
		choice := ui.PrintMenu(title, options)

		// Hay que mapear la opción elegida según si está logueado o no.
		if c.currentUser == "" {
			// Caso NO logueado
			switch choice {
			case 1:
				c.registerUser()
			case 2:
				c.loginUser()
			case 3:
				// Opción Salir
				c.log.Println("Saliendo del cliente...")
				return
			}
		} else {
			// Caso logueado
			switch choice {
			case 1:
				c.fetchData()
			case 2:
				c.updateData()
			case 3:
				c.logoutUser()
			case 4:
				// Opción Salir
				c.log.Println("Saliendo del cliente...")
				return
			}
		}

		// Pausa para que el usuario vea resultados.
		ui.Pause("Pulsa [Enter] para continuar...")
	}
}

// registerUser pide credenciales y las envía al servidor para un registro.
// Si el registro es exitoso, se intenta el login automático.
func (c *client) registerUser() {
	ui.ClearScreen()
	fmt.Println("** Registro de usuario **")

	username := ui.ReadInput("Nombre de usuario")
	password := ui.ReadInput("Contraseña")

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte(password + username)) //Combinacion de usuario y contraseña para que sea unica dado que las contraseñas puedencoincidir
	keyLogin := keyClient[:32]                              // una mitad para el login (256 bits)
	keyData := keyClient[32:64]                             // la otra para los datos (256 bits)

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
		c.log.Println("Registro exitoso; intentando login automático...")

		loginRes := c.sendRequest(api.Request{
			Action:   api.ActionLogin,
			Username: username,
			Password: encode64(keyLogin),
		})
		if loginRes.Success {
			fullHash := sha512.Sum512([]byte(username + password))
			key = fullHash[:24]
			c.currentUser = username
			c.authToken = loginRes.Token
			fmt.Println("Login automático exitoso. Token guardado.")
		} else {
			fmt.Println("No se ha podido hacer login automático:", loginRes.Message)
		}
	}
}

// loginUser pide credenciales y realiza un login en el servidor.
func (c *client) loginUser() {
	ui.ClearScreen()
	fmt.Println("** Inicio de sesión **")

	username := ui.ReadInput("Nombre de usuario")
	password := ui.ReadSecretInput("Contraseña: ")

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
		fullHash := sha512.Sum512([]byte(username + password))
		key = fullHash[:24]
		c.currentUser = username
		c.authToken = res.Token
		fmt.Println("Sesión iniciada con éxito. Token guardado.")
	}
}

// fetchData pide datos privados al servidor.
// El servidor devuelve la data asociada al usuario logueado.
func (c *client) fetchData() {
	ui.ClearScreen()
	fmt.Println("** Obtener datos del usuario **")

	// Chequeo básico de que haya sesión
	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		c.currentUser = ""
		c.authToken = ""
		key = nil
		return
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

		for i, data := range dataList {
			// Convertimos a []byte
			encryptedData := decode64(data)

			// Desencriptamos
			jData := decrypt(encryptedData, key)

			// Convertimos a struct
			var clinicData api.ClinicData
			json.Unmarshal(jData, &clinicData)
			fmt.Println("----------------------")
			fmt.Println("Paciente N: ", i+1)
			fmt.Println("ID: ", clinicData.ID)
			fmt.Println("Nombre: ", clinicData.Name)
			fmt.Println("Apellidos: ", clinicData.SureName)
			fmt.Println("Edad: ", clinicData.Edad)
			fmt.Println("Sexo: ", clinicData.Sexo)
			fmt.Println("SIP: ", clinicData.SIP)
			fmt.Println("Procedencia: ", clinicData.Procedencia)
			fmt.Println("Motivo: ", clinicData.Motivo)
			fmt.Println("Enfermedad: ", clinicData.Enfermedad)
		}
		for {
			del := ui.ReadInput("Modificar expediente (S/N)")
			if del == "S" || del == "s" {
				c.modData(dataList)
				break
			}
			mod := ui.ReadInput("Borrar expediente (S/N)")
			if mod == "S" || mod == "s" {
				c.delData(dataList)
				break
			}
			if mod == "N" || del == "N" || mod == "n" || del == "n" {
				break
			}
		}
	} else {
		c.currentUser = ""
		c.authToken = ""
		key = nil
	}
}

func (c *client) modData(listData []string) {
	conf := ui.ReadInput("Seguro que deseas modificar el expediente? (S/N)")
	if conf == "S" || conf == "s" {
		if c.currentUser == "" || c.authToken == "" {
			fmt.Println("No estás logueado. Inicia sesión primero.")
			c.currentUser = ""
			c.authToken = ""
			key = nil
			return
		}

		id := ui.ReadInt("Seleccione el ID")

		var data api.ClinicData
		posicion := -1

		for i, elem := range listData {
			// Convertimos a []byte
			encryptedData := decode64(elem)

			// Desencriptamos
			jData := decrypt(encryptedData, key)

			// Convertimos a struct
			json.Unmarshal(jData, &data)

			// Condicion
			if id == data.ID {
				posicion = i
				break
			}
		}
		if posicion == -1 {
			fmt.Println("El ID no se encuentra entre los expedientes admitidos")
			return
		}

		// Inicializa un struct de Datos de expediente
		newData := api.ClinicData{
			ID:          data.ID,
			Name:        data.Name,
			SureName:    data.SureName,
			Edad:        data.Edad,
			Sexo:        data.Sexo,
			SIP:         data.SIP,
			Procedencia: data.Procedencia,
			Motivo:      data.Motivo,
			Enfermedad:  data.Enfermedad,
		}

		newData.Name = ui.ReadInput("Nombre " + newData.Name)
		newData.SureName = ui.ReadInput("Apellido " + newData.SureName)
		newData.Edad = ui.ReadInt("Edad " + strconv.Itoa(newData.Edad))
		newData.Sexo = ui.ReadInput("Sexo " + newData.Sexo)
		newData.SIP = ui.ReadInt("SIP " + strconv.Itoa(newData.SIP))
		newData.Procedencia = ui.ReadInput("Procedencia " + newData.Procedencia)
		newData.Motivo = ui.ReadInput("Motivo " + newData.Motivo)
		newData.Enfermedad = ui.ReadInput("Enfermedad " + newData.Enfermedad)

		// Convertimos a JSON
		jData, err := json.Marshal(newData)
		if err != nil {
			fmt.Println("Error en Marshal 315")
			return
		}

		// Encryptamos
		encriptedData := encrypt(jData, key)

		// Conversion a string
		sendData := encode64(encriptedData)

		// Enviamos la solicitud de actualización
		res := c.sendRequest(api.Request{
			Action:   api.ActionModData,
			Username: c.currentUser,
			Token:    c.authToken,
			Data:     sendData,
			Position: posicion,
		})

		fmt.Println("Éxito:", res.Success)
		fmt.Println("Mensaje:", res.Message)
		if !res.Success {
			c.currentUser = ""
			c.authToken = ""
			key = nil
		}
	} else {
		fmt.Println("Cancelar modificación")
		return
	}
}

func (c *client) delData(listData []string) {
	conf := ui.ReadInput("Seguro que deseas borrar el expediente? (S/N)")
	if conf == "S" || conf == "s" {
		if c.currentUser == "" || c.authToken == "" {
			fmt.Println("No estás logueado. Inicia sesión primero.")
			c.currentUser = ""
			c.authToken = ""
			key = nil
			return
		}

		id := ui.ReadInt("Seleccione el ID")

		var data api.ClinicData
		posicion := -1

		for i, elem := range listData {
			// Convertimos a []byte
			encryptedData := decode64(elem)

			// Desencriptamos
			jData := decrypt(encryptedData, key)

			// Convertimos a struct
			json.Unmarshal(jData, &data)

			// Condicion
			if id == data.ID {
				posicion = i
				break
			}
		}
		if posicion == -1 {
			fmt.Println("El ID no se encuentra entre los expedientes admitidos")
			return
		}

		// Enviamos la solicitud de actualización
		res := c.sendRequest(api.Request{
			Action:   api.ActionDelData,
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
			return
		}
	} else {
		fmt.Println("Cancelar borrado")
		return
	}
}

// updateData pide nuevo texto y lo envía al servidor con ActionUpdateData.
func (c *client) updateData() {
	ui.ClearScreen()
	fmt.Println("** Actualizar datos del usuario **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		c.currentUser = ""
		c.authToken = ""
		key = nil
		return
	}

	// Inicializa un struct de Datos de expediente
	newData := api.ClinicData{
		ID:          0,
		Name:        "",
		SureName:    "",
		Edad:        0,
		Sexo:        "",
		SIP:         0,
		Procedencia: "",
		Motivo:      "",
		Enfermedad:  "",
	}

	// Leemos la nueva Data
	newData.Name = ui.ReadInput("Introduce el nombre del usuario")
	newData.SureName = ui.ReadInput("Introduce el apellido del usuario")
	newData.Edad = ui.ReadInt("Introduce la edad del usuario")
	newData.Sexo = ui.ReadInput("Introduce el sexo del usuario")
	newData.SIP = ui.ReadInt("Introduce el SIP del usuario")
	newData.Procedencia = ui.ReadInput("Introduce la procedencia del usuario")
	newData.Motivo = ui.ReadInput("Introduce el motivo del usuario")
	newData.Enfermedad = ui.ReadInput("Introduce la enfermedad del usuario")

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
		fmt.Println(res1.Message)
		c.currentUser = ""
		c.authToken = ""
		key = nil
		return
	}

	// Convertimos a JSON
	jData, err := json.Marshal(newData)
	if err != nil {
		fmt.Println("Error en Marshal 262")
		return
	}

	// Encryptamos
	encriptedData := encrypt(jData, key)

	// Conversion a string
	data := encode64(encriptedData)

	// Enviamos la solicitud de actualización
	res2 := c.sendRequest(api.Request{
		Action:   api.ActionUpdateData,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     data,
	})

	fmt.Println("Éxito:", res2.Success)
	fmt.Println("Mensaje:", res2.Message)
	if !res2.Success {
		c.currentUser = ""
		c.authToken = ""
		key = nil
	}
}

// logoutUser llama a la acción logout en el servidor, y si es exitosa,
// borra la sesión local (currentUser/authToken).
func (c *client) logoutUser() {
	ui.ClearScreen()
	fmt.Println("** Cerrar sesión **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		c.currentUser = ""
		c.authToken = ""
		key = nil
		return
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
}

// sendRequest envía un POST JSON a la URL del servidor y
// devuelve la respuesta decodificada. Se usa para todas las acciones.
func (c *client) sendRequest(req api.Request) api.Response {
	jsonData, _ := json.Marshal(req)

	// Configurar transporte con TLS (permitiendo certificados autofirmados).
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
