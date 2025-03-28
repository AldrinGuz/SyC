import './style.css';
import './app.css';


import * as App from '../wailsjs/go/main/App';

document.querySelector('#app').innerHTML = `

    <div class="result" id="result">Haga login o registrese en nuestra app.</div>
      <div class="input-box" id="input">
        <label for="name">Nombre:</label>
        <input class="input" id="name" type="text" autocomplete="off" />
        <label for="password">Contraseña:</label>
        <input class="input" id="password" type="password" />
        <button class="btn" onclick="loggin()">Login</button>
        <button class="btn" onclick="panel('register')">Registrar</button>
      </div>
    </div>
`;

window.loggin = function () {
    let name = document.getElementById("name").value;
    let pass = document.getElementById("password").value;

    // Check if the input is empty
    if (name === ""){
        errorWindow("Falta el nombre.");
        return;
    }
    if (pass === ""){
        errorWindow("Falta la contraseña.");
        return;
    };

    try {
        App.Loggin(name,pass)
            .then((result) => {
                if (result == true){
                    panel('main');
                }else{
                    errorWindow("No se ha podido logear el usuario");
                }
            })
            .catch((err) => {
                console.error(err);
            });
    } catch (err) {
        console.error(err);
    }
};
window.register = function(){
    let name = document.getElementById("name").value;
    let pass = document.getElementById("password").value;

    // Check if the input is empty
    if (name === ""){
        errorWindow("Falta el nombre.");
        return;
    }
    if (pass === ""){
        errorWindow("Falta la contraseña.");
        return;
    };

    try{
        App.Register(name,pass).then((result)=>{
            if (result == true){
                panel('main');
            }else{
                errorWindow("No se ha posidido registrar ese usuario");
            }
        })
    }catch(err){
        console.error(err);
    }
}
window.logout = function(){
    try{
        App.Logout().then((result)=>{
            if(result==true){
                panel('login');
            }else{
                errorWindow("Ha ocurrido un problema cierra la aplicación");
            }
        })
    }catch(err){
        console.error(err);
    }
}
window.updateData = function(){
    let datos ={
        Name:"",
        SureName:"",
        ID:0,
        NumHisClin:0,
	    Edad:0,
    	Sexo:"",
    	EstadoCivil:"",
    	Ocupacion:"",
    	Procedencia:"",
    	Motivo:"",
    	Enfermedad:""
    }
    datos.Name = document.getElementById("nombre").value;
    datos.SureName = document.getElementById("apellidos").value;
    datos.ID = parseInt(document.getElementById("ID").value);
    let datosJ = JSON.stringify(datos)
    console.log(datosJ)
    
    let res = document.getElementById("resultData");
    res.remove();
    res = document.createElement("p");
    res.setAttribute("id","resultData");
    res.innerText="Cargando ...";
    document.getElementById("input").appendChild(res);

    try{
        App.UpdateData(datosJ).then((result)=>{
            if(result == true){
                res.innerText="Los datos se han enviado con éxito"
            }else{
                res.innerText="Error: los datos no se han enviado"
            }
        })
    }catch(err){
        console.error(err)
    }
}
window.getData = function(){
    let res = document.getElementById("resultData");
    try{
        App.GetData().then((result)=>{
            if (result === "/Error: 503 Service Unavailable*"){
                res.innerText = "Ha habido un error con el servidor";
            }else if(result === "/Error: 401 Unauthorized*"){
                res.innerText = "Ha habido un error interno, reinicia la aplicación";
            }else if(result ==="/Error: Fallo en la conversión de datos"){
                res.innerText = "Ha habido un error en la aplicación. Contacte con el soporte técnico"
            }
            else{
                res.innerText = "Tus datos: " + result; 
            }
        })
    }catch(err){
        console.error(err)
    }
}
window.panel = function(tipo){
    switch (tipo){
        case "login":
            document.querySelector('#app').innerHTML = `
            <div class="result" id="result">Haga login o registrese en nuestra app.</div>
            <div class="input-box" id="input">
                <label for="name">Nombre:</label>
                <input class="input" id="name" type="text" autocomplete="off" />
                <label for="password">Contraseña:</label>
                <input class="input" id="password" type="password" />
                <button class="btn" onclick="loggin()">Login</button>
                <button class="btn" onclick="panel('register')">Registrar</button>
            </div>
            `;
            break;
        case "register":
            document.querySelector('#app').innerHTML = `
            <div class="result" id="result">Registrar</div>
            <p>Por favor, complete todos los campos 👇</p>
            <div class="input-box" id="input">
                <label for="data">Nombre:</label>
                <input class="input" id="name" type="text" autocomplete="off" />
                <label for="password">Contraseña:</label>
                <input class="input" id="password" type="password" autocomplete="off" />
                <button class="btn" onclick="register()">Registrar</button>
                <button class="btn" onclick="panel('login')">Volver</button>
            </div>
            `;
            break;
        case "main":
            document.querySelector('#app').innerHTML = `
            <div class="result" id="result">Bienvenido</div>
            <div class="input-box" id="input">
                <p>Estas dentro del menu principal</p>
                <label for="nombre">Nombre:</label>
                <input class="input" id="nombre" type="text" autocomplete="off" />
                <label for="apellidos">Apellidos:</label>
                <input class="input" id="apellidos" type="text" autocomplete="off" />
                <label for="ID">NIE:</label>
                <input class="input" id="ID" type="number" autocomplete="off" />
                <button class="btn" onclick="getData()">Datos</button>
                <button class="btn" onclick="updateData()">Actualizar</button>
                <button class="btn" onclick="logout()">Desconectar</button>
                <p id="resultData"></p>
            </div>
            `;
            break;
        default:
            document.getElementById("result").innerText = "Bad request"
            break;
    }
}
window.errorWindow = function(mensaje){
    if (document.getElementById("errMess")!=null){
        document.getElementById("errMess").remove();
    }
    let node = document.createElement("div");
    node.setAttribute("id","errMess");
    node.setAttribute("class","errWin");
    let m = document.createElement("p");
    m.innerText=mensaje;
    let close = document.createElement("button");
    close.setAttribute("id","closeBtn");
    close.setAttribute("onclick","closeErr()")
    close.innerText="X";
    node.appendChild(m);
    node.appendChild(close);
    document.querySelector('#app').appendChild(node);
}
window.closeErr = function(){
    if (document.getElementById("errMess")!=null){
        document.getElementById("errMess").remove();
    }   
}