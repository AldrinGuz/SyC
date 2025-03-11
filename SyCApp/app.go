package main

import (
	"SyCApp/backend/api"
	"bytes"
	"context"
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
	return true
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

	// Enviamos la acción al servidor
	res := c.sendRequest(api.Request{
		Action:   api.ActionRegister,
		Username: username,
		Password: password,
	})

	// Mostramos resultado
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, probamos loguear automáticamente.
	if res.Success {
		loginRes := c.sendRequest(api.Request{
			Action:   api.ActionLogin,
			Username: username,
			Password: password,
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

	res := c.sendRequest(api.Request{
		Action:   api.ActionLogin,
		Username: username,
		Password: password,
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
func (c *client) fetchData() {
	fmt.Println("** Obtener datos del usuario **")

	// Chequeo básico de que haya sesión
	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
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
		fmt.Println("Tus datos:", res.Data)
	}
}

// updateData pide nuevo texto y lo envía al servidor con ActionUpdateData.
func (c *client) updateData(datos string) {
	fmt.Println("** Actualizar datos del usuario **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// Leemos la nueva Data
	newData := datos

	// Enviamos la solicitud de actualización
	res := c.sendRequest(api.Request{
		Action:   api.ActionUpdateData,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     newData,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
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
	resp, err := http.Post("http://localhost:8080/api", "application/json", bytes.NewBuffer(jsonData))
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
