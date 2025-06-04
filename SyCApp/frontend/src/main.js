import './style.css';


import * as App from '../wailsjs/go/main/App';

document.querySelector('#app').innerHTML = `
            <div id="loading" style="display: block;">
    <div class="container2">
        <div class="load">
            <h1>CARGANDO</h1>
            <div class="box-item first">.</div>
            <div class="box-item second">.</div>
            <div class="box-item third">.</div>
        </div>
    </div>
</div>
`;

let rol;
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
                if (result == "Requiere 2FA"){
                    user1 = name;
                    pass1 = pass;
                    panel('2FA');
                }else if (result.includes("Autorizado")){
                    if(result.includes("patient")){
                        rol = "patient"
                    }else{
                        rol = "doctor"
                    }
                    user1 = ""
                    pass1 = ""
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
let user1
let pass1
window.auth2FA = function() {
    let code = document.getElementById("data").value;
    try {
        App.Auth2FA(user1,pass1,code).then((result)=>{
            if(result.includes("Autorizado")){
                if(result.includes("patient")){
                    rol = "patient"
                }else{
                    rol = "doctor"
                }
                user1 = ""
                pass1 = ""
                panel('main')
            }else{
                errorWindow("Código incorrecto")
            }
        })
    } catch (error) {
        console.error(error);
    }    
}
window.register = function(){
    let name = document.getElementById("name").value;
    let pass = document.getElementById("password").value;
    let rep = document.getElementById("repPassword").value;
    let sip = document.getElementById("SIP").value;

    // Check if the input is empty
    if (name === ""){
        errorWindow("Falta el nombre.");
        return;
    }
    if (pass === ""){
        errorWindow("Falta la contraseña.");
        return;
    };
    if (sip === ""){
        errorWindow("Falta el SIP.");
        return;
    };
    if (rep != pass){
        errorWindow("Las contraseñas no coinciden.");
    }

    let numSIP = parseInt(sip)
    try{
        App.Register(name, pass, numSIP).then((result) => {
            if (result != "") {
                panel('TOTP');
                let QR = document.getElementById("QRcode");
                
                // Crear un elemento img
                let img = document.createElement("img");
                
                // Asignar los datos de la imagen (asumiendo que result es base64)
                img.src = "data:image/png;base64," + result; // Cambia "png" por el formato correcto si es necesario
                
                // Limpiar el div y añadir la imagen
                QR.innerHTML = "";
                QR.appendChild(img);
            } else {
                errorWindow("No se ha podido registrar ese usuario");
            }
        });
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
	    Edad:0,
    	Sexo:"",
        SIP:0,
    	Procedencia:"",
    	Motivo:"",
    	Enfermedad:""
    }
    datos.Name = document.getElementById("Nombre").value;
    datos.SureName = document.getElementById("Apellidos").value;
    datos.Edad = parseInt(document.getElementById("Edad").value);
    datos.Sexo = document.getElementById("Sexo").value;
    datos.SIP = parseInt(document.getElementById("SIP").value);
    datos.Procedencia = document.getElementById("Procedencia").value;
    datos.Motivo = document.getElementById("Motivo").value;
    datos.Enfermedad = document.getElementById("Enfermedad").value;
    let datosJ = JSON.stringify(datos)
    
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
                logout()
            }
        })
    }catch(err){
        console.error(err)
    }
}
window.getData = function(){
    panel('data');
    let res = document.getElementById("resultData");
    res.remove();
    res = document.createElement("p");
    res.setAttribute("id","resultData");
    document.getElementById("input").appendChild(res);
    let tableExp = document.getElementById("tableExp");
    tableExp.innerHTML=`
        <tr>
            <th>N</th>
            <th>ID</th>
            <th>SIP</th>
            <th>Nombre</th>
            <th>Apellidos</th>
            <th>Edad</th>
            <th>Sexo</th>
            <th>Procedencia</th>
            <th>Consulta</th>
            <th>Enfermedad</th>
        </tr>
    `;
    try{
        App.GetData().then((result)=>{
            if (result === "/Error: 503 Service Unavailable*"){
                res.innerText = "Ha habido un error con el servidor";
            }else if(result === "/Error: 401 Unauthorized*"){
                res.innerText = "Ha habido un error interno, reinicia la aplicación";
                logout()
            }else if(result ==="/Error: Fallo en la conversión de datos"){
                res.innerText = "Ha habido un error en la aplicación. Contacte con el soporte técnico"
                logout()
            }
            else{
                let dataList = JSON.parse(result);
                for (let i = 0; i < dataList.length; i++) {
                    var data = dataList[i];
                    var node = document.createElement("tr");
                    node.setAttribute("id",data.id);
                    node.setAttribute("class","temp");
                    node.setAttribute("style","cursor: pointer;");
                    node.innerHTML = "<th>"+(i+1)+"</th>"+"<th>"+data.id+"</th><th>"+data.sip+"</th><th>"+data.name+"</th><th>"+data.surename+"</th><th>"+data.edad+"</th><th>"+data.sexo+"</th><th>"+data.procedencia+"</th><th>"+data.motivo+"</th><th>"+data.enfermedad+"</th>";
                    tableExp.appendChild(node);
                }
                if (rol != "patient"){
                    var x = document.getElementsByClassName("temp")
                    for (let i = 0; i < x.length; i++){
                        for (let j = 0; j < x.item(i).children.length - 1; j++){
                            x.item(i).children.item(j).setAttribute("onclick","modify("+x.item(i).attributes.id.value+",'modExp')")
                        }
                    }
                }
            }
        })
    }catch(err){
        console.error(err)
    }
}
window.modify = function(id,s){
    panel(s);
    let btnMod = document.getElementById("btnModData");
    btnMod.setAttribute("onclick","modData("+id+")");
    let btnDel = document.getElementById("btnDelData");
    btnDel.setAttribute("onclick","delData("+id+")");
}
window.modData = function(ID){
    let id = 0;
    id = ID;
    let datos ={
        Name:"",
        SureName:"",
        ID:id,
	    Edad:0,
    	Sexo:"",
        SIP:0,
    	Procedencia:"",
    	Motivo:"",
    	Enfermedad:""
    }
    datos.Name = document.getElementById("Nombre").value;
    datos.SureName = document.getElementById("Apellidos").value;
    datos.Edad = parseInt(document.getElementById("Edad").value);
    datos.Sexo = document.getElementById("Sexo").value;
    datos.SIP = parseInt(document.getElementById("SIP").value);
    datos.Procedencia = document.getElementById("Procedencia").value;
    datos.Motivo = document.getElementById("Motivo").value;
    datos.Enfermedad = document.getElementById("Enfermedad").value;
    let datosJ = JSON.stringify(datos)
    
    let res = document.getElementById("resultData");
    res.remove();
    res = document.createElement("p");
    res.setAttribute("id","resultData");
    res.innerText="Cargando ...";
    document.getElementById("input").appendChild(res);

    try{
        App.ModData(datosJ,id).then((result)=>{
            if(result == true){
                res.innerText="El expediente se ha modificado con exito"
            }else{
                res.innerText="Error: no se ha modificado"
            }
        })
    }catch(err){
        console.error(err)
    }
}
window.delData = function(id){
    let res = document.getElementById("resultData");
    res.remove();
    res = document.createElement("p");
    res.setAttribute("id","resultData");
    res.innerText="Cargando ...";
    document.getElementById("input").appendChild(res);
    try{
        App.DelData(id).then((result)=>{
            if(result == true){
                res.innerText="El expediente se ha eliminado con exito"
            }else{
                res.innerText="Error: no se ha eliminado"
            }
        })
    }catch(err){
        console.error(err)
    }
}
window.panel = function(tipo){
    switch (tipo){
        case "loading":
            document.querySelector('#app').innerHTML = `
            <div id="loading" style="display: block;">
    <div class="container2">
        <div class="load">
            <h1>CARGANDO</h1>
            <div class="box-item first">.</div>
            <div class="box-item second">.</div>
            <div class="box-item third">.</div>
        </div>
    </div>
</div>
            `;
            break;
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
                <label for="data">(*)Nombre:</label>
                <input class="input" id="name" type="text" autocomplete="off" />
                <label for="password">(*)Contraseña:</label>
                <input class="input" id="password" type="password" autocomplete="off" />
                <label for="repPassword">(*)Repita la contraseña:</label>
                <input class="input" id="repPassword" type="password" autocomplete="off" />
                <label for="SIP">(*)Introduzca su targeta SIP:</label>
                <input class="input" id="SIP" type="password" autocomplete="off" />
                <button class="btn" onclick="register()">Registrar</button>
                <button class="btn" onclick="panel('login')">Volver</button>
            </div>
            `;
            break;
        case "TOTP":
            document.querySelector('#app').innerHTML = `
            <div class="result" id="result">Registrar</div>
            <p>Por favor, utiliza tu aplicación autentificadora y escanea el siguiente QR</p>
            <div class="input-box" id="input">
                <div id="QRcode"></div>
                <button class="btn" id="continue" onclick="panel('login')">Continuar</button>
            </div>
            `;
            break;
        case "2FA":
            document.querySelector('#app').innerHTML = `
            <div class="result" id="result">Registrar</div>
            <p>Autenticación en dos factores requerida</p>
            <div class="input-box" id="input">
                <label for="data">(*)Código de su aplicación authentificadoras:</label>
                <input class="input" id="data" type="text" autocomplete="off" />
                <button class="btn" id="2FA" onclick="auth2FA()">Entrar</button>
            </div>
            `;
            break;
        case "main":
            document.querySelector('#app').innerHTML = `
            <div class="result" id="result">Bienvenido</div>
            <p>Estas dentro del menu principal</p>
            <div class="input-box" id="input">
                <button class="btn" id="getData" onclick="getData()">Datos</button>
                <button class="btn" id="newExp" onclick="panel('newExp')">Crear Expediente</button>
                <button class="btn" id="manageFA" onclick="panel('manageFA')">Factor de Autentificación</button>
                <button class="btn" id="logout" onclick="logout()">Desconectar</button>
                <p id="resultData"></p>
            </div>
            `;
            break;
        case "newExp":
            document.querySelector('#app').innerHTML = `
            <div class="result" id="result">Crear expediente</div>
            <p>Por favor, complete todos los campos (*) 👇</p>
            <div class="input-box" id="input">
                <label for="Nombre">(*)Nombre:</label>
                <input class="input" id="Nombre" type="text" autocomplete="off" />
                <label for="Apellidos">(*)Apellidos:</label>
                <input class="input" id="Apellidos" type="text" autocomplete="off" />
                <label for="SIP">(*)SIP:</label>
                <input class="input" id="SIP" type="number" autocomplete="off" />
                <label for="Edad">(*)Edad:</label>
                <input class="input" id="Edad" type="number" autocomplete="off" />
                <label for="Sexo">(*)Sexo:</label>
                <select name="Sexo" id="Sexo">
                    <option value="Hombre">Hombre</option>
                    <option value="Mujer">Mujer</option>
                    <option value="No binario">Otro</option>
                    <option value="Indeterminado">Prefiero no comunicarlo</option>
                </select>
                <label for="Procedencia">(*)Procedencia del usuario:</label>
                <input class="input" id="Procedencia" type="text" autocomplete="off" />
                <label for="Motivo">(*)Motivo de consulta:</label>
                <input class="input" id="Motivo" type="text" autocomplete="off" />
                <label for="Enfermedad">(*)Enfermedad:</label>
                <input class="input" id="Enfermedad" type="text" autocomplete="off" />
                <button class="btn" onclick="updateData()">Crear</button>
                <button class="btn" onclick="panel('main')">Volver</button>
                <p id="resultData"></p>
            </div>
            `;
            break;
        case "modExp":
            document.querySelector('#app').innerHTML = `
            <div class="result" id="result">Crear expediente</div>
            <p>Por favor, complete todos los campos (*) 👇</p>
            <div class="input-box" id="input">
                <label for="Nombre">(*)Nombre:</label>
                <input class="input" id="Nombre" type="text" autocomplete="off" />
                <label for="Apellidos">(*)Apellidos:</label>
                <input class="input" id="Apellidos" type="text" autocomplete="off" />
                <label for="SIP">(*)SIP:</label>
                <input class="input" id="SIP" type="number" autocomplete="off" />
                <label for="Edad">(*)Edad:</label>
                <input class="input" id="Edad" type="number" autocomplete="off" />
                <label for="Sexo">(*)Sexo:</label>
                <select name="Sexo" id="Sexo">
                    <option value="Hombre">Hombre</option>
                    <option value="Mujer">Mujer</option>
                    <option value="No binario">Otro</option>
                    <option value="Indeterminado">Prefiero no comunicarlo</option>
                </select>
                <label for="Procedencia">(*)Procedencia del usuario:</label>
                <input class="input" id="Procedencia" type="text" autocomplete="off" />
                <label for="Motivo">(*)Motivo de consulta:</label>
                <input class="input" id="Motivo" type="text" autocomplete="off" />
                <label for="Enfermedad">(*)Enfermedad:</label>
                <input class="input" id="Enfermedad" type="text" autocomplete="off" />
                <button id="btnModData" class="btn" onclick="modData()">Actualizar</button>
                <button id="btnDelData" class="btn" onclick="delData()">Borrar</button>
                <button class="btn" onclick="getData()">Volver</button>
                <p id="resultData"></p>
            </div>
            `;
            break;
        case "data":
            document.querySelector('#app').innerHTML = `
            <div class="result" id="result"></div>
            <p>Todos los pacientes actuales</p>
            <table id="tableExp">
                <tr>
                    <th>ID</th>
                    <th>N Exp</th>
                    <th>DNI/NIE</th>
                    <th>Nombre</th>
                    <th>Apellidos</th>
                    <th>Edad</th>
                    <th>Sexo</th>
                    <th>Consulta</th>
                    <th>Enfermedad</th>
                </tr>
            </table>
            <div class="input-box" id="input">
                <button class="btn" onclick="panel('main')">Volver</button>
            </div>
            <p id="resultData"></p>
            `;
            break;
        case "manageFA":
            document.querySelector('#app').innerHTML = `
            <div class="result" id="result">2FA TOTP</div>
            <p>AVISO: Se recomienda mantener el 2FA siempre habilitado por su seguridad.</p>
            <div class="input-box" id="input">
                <button class="btn" id="hab" onclick="manage2FA('true')">Habilitar / Crear QR</button>
                <button class="btn" id="deshab" onclick="manage2FA('false')">Deshabilitar</button>
                <button class="btn" onclick="panel('main')">Volver</button>
                <p id="resultData"></p>
            </div>
            `;
            break;
        default:
            document.getElementById("result").innerText = "Bad request"
            break;
    }
    if (rol == "patient" && document.getElementById("result").innerText == "Bienvenido"){
        document.getElementById("newExp").remove()
        document.getElementById("manageFA").remove()
    }
}
window.manage2FA = function(select){// select true
    let shutdown = true;
    if (select == "false"){
        shutdown = false;
    }
    try {
        App.Manage2FA(shutdown).then((result)=>{
            if (result.includes("deshabilitada")){
                errorWindow(result);
            }else if (result == ""){
                errorWindow("Algo ha salido mal");
            }else{
                panel('TOTP');
                let button = document.getElementById("continue")
                button.setAttribute("onclick","panel('main')")
                let QR = document.getElementById("QRcode");
                
                // Crear un elemento img
                let img = document.createElement("img");
                
                // Asignar los datos de la imagen (asumiendo que result es base64)
                img.src = "data:image/png;base64," + result; // Cambia "png" por el formato correcto si es necesario
                
                // Limpiar el div y añadir la imagen
                QR.innerHTML = "";
                QR.appendChild(img);
            }
        })
    } catch (error) {
        console.error(error)
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
function showLoading(duration, nextPanel) {
    panel('loading');
    setTimeout(() => { panel(nextPanel); }, duration);
}
showLoading(2000, 'login');