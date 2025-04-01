import './style.css';


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
    datos.NumHisClin = parseInt(document.getElementById("N_Exp").value);
    datos.Edad = parseInt(document.getElementById("Edad").value);
    datos.Sexo = document.getElementById("apellidos").value;
    datos.Motivo = document.getElementById("Motivo").value;
    datos.Enfermedad = document.getElementById("Enfermedad").value;
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
    panel('data');
    let tableExp = document.getElementById("tableExp");
    tableExp.innerHTML=`
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
    `;
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
                let dataList = JSON.parse(result);
                console.log(dataList)
                for (let i = 0; i < dataList.length; i++) {
                    var data = dataList[i];
                    var node = document.createElement("tr");
                    node.setAttribute("id",data.ID);
                    node.setAttribute("class","temp");
                    node.setAttribute("style","cursor: pointer;");
                    node.innerHTML = "<th>"+(i+1)+"</th>"+"<th>"+data.NumHisClin+"</th><th>"+data.ID+"</th><th>"+data.Name+"</th><th>"+data.SureName+"</th><th>"+data.Edad+"</th><th>"+data.Sexo+"</th><th>"+data.Motivo+"</th><th>"+data.Enfermedad+"</th>";
                    tableExp.appendChild(node);
                }
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
            <p>Estas dentro del menu principal</p>
            <div class="input-box" id="input">
                <button class="btn" onclick="getData()">Datos</button>
                <button class="btn" onclick="panel('newExp')">Crear Expediente</button>
                <button class="btn" onclick="logout()">Desconectar</button>
                <p id="resultData"></p>
            </div>
            `;
            break;
        case "newExp":
            document.querySelector('#app').innerHTML = `
            <div class="result" id="result">Crear expediente</div>
            <p>Por favor, complete todos los campos 👇</p>
            <div class="input-box" id="input">
                <label for="nombre">Nombre:</label>
                <input class="input" id="nombre" type="text" autocomplete="off" />
                <label for="apellidos">Apellidos:</label>
                <input class="input" id="apellidos" type="text" autocomplete="off" />
                <label for="ID">NIE:</label>
                <input class="input" id="ID" type="number" autocomplete="off" />
                <label for="N_Exp">Nº Expediente:</label>
                <input class="input" id="N_Exp" type="number" autocomplete="off" />
                <label for="Edad">Edad:</label>
                <input class="input" id="Edad" type="number" autocomplete="off" />
                <label for="Sexo">Sexo:</label>
                <input class="input" id="Sexo" type="text" autocomplete="off" />
                <label for="Motivo">Motivo de consulta:</label>
                <input class="input" id="Motivo" type="text" autocomplete="off" />
                <label for="Enfermedad">Enfermedad:</label>
                <input class="input" id="Enfermedad" type="text" autocomplete="off" />
                <button class="btn" onclick="updateData()">Crear</button>
                <button class="btn" onclick="panel('main')">Volver</button>
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