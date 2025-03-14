import './style.css';
import './app.css';


import * as App from '../wailsjs/go/main/App';

document.querySelector('#app').innerHTML = `

    <div class="result" id="result">Please enter your name below 👇</div>
      <div class="input-box" id="input">
        <input class="input" id="name" type="text" autocomplete="off" />
        <input class="input" id="password" type="password" />
        <button class="btn" onclick="loggin()">Login</button>
        <button class="btn" onclick="panelRegister()">Registrar</button>
      </div>
    </div>
`;

window.loggin = function () {
    let name = document.getElementById("name").value;
    let pass = document.getElementById("password").value;

    // Check if the input is empty
    if (name === "") return;
    if (pass === "") return;

    try {
        App.Loggin(name,pass)
            .then((result) => {
                if (result == true){
                    document.querySelector('#app').innerHTML = `
                        <div class="result" id="result">Bienvenido</div>
                        <div class="input-box" id="input">
                            <p>Estas dentro del menu principal</p>
                            <input class="input" id="data" type="text" autocomplete="off" />
                            <button class="btn" onclick="getData()">Datos</button>
                            <button class="btn" onclick="updateData()">Actualizar</button>
                            <button class="btn" onclick="logout()">Desconectar</button>
                            <p id="resultData"></p>
                        </div>
                    `;
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
    if (name === "") return;
    if (pass === "") return;

    try{
        App.Register(name,pass).then((result)=>{
            if (result == true){
                document.querySelector('#app').innerHTML = `
                <div class="result" id="result">Bienvenido</div>
                <div class="input-box" id="input">
                    <p>Estas dentro del menu principal</p>
                    <input class="input" id="data" type="text" autocomplete="off" />
                    <button class="btn" onclick="getData()">Datos</button>
                    <button class="btn" onclick="updateData()">Actualizar</button>
                    <button class="btn" onclick="logout()">Desconectar</button>
                    <p id="resultData"></p>
                </div>
                `;
            }else{
                document.getElementById("result").innerText="Ha habido un error"
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
                document.querySelector('#app').innerHTML = `
                    <div class="result" id="result">Please enter your name below 👇</div>
                    <div class="input-box" id="input">
                        <input class="input" id="name" type="text" autocomplete="off" />
                        <input class="input" id="password" type="password" />
                        <button class="btn" onclick="loggin()">Login</button>
                        <button class="btn" onclick="panelRegister()">Registrar</button>
                    </div>
                    </div>
                `;
            }else{
                document.getElementById("result").innerText="Ha ocurrido un problema"
            }
        })
    }catch(err){
        console.error(err);
    }
}
window.updateData = function(){
    let datos = document.getElementById("data").value;
    let res = document.getElementById("resultData");
    res.remove();
    res = document.createElement("p");
    res.setAttribute("id","resultData");
    res.innerText="Cargando ...";
    document.getElementById("input").appendChild(res);

    try{
        App.UpdateData(datos).then((result)=>{
            if(result == true){
                res.innerText="Los datos se han enviado con éxito"
            }else{
                res.innerText="Erro: los datos no se han enviado"
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
            }else{
                res.innerText = "Tus datos: " + result;
            }
        })
    }catch(err){
        console.error(err)
    }
}
window.panelRegister = function(){
    document.querySelector('#app').innerHTML = `
        <div class="result" id="result">Registrar</div>
        <div class="input-box" id="input">
            <input class="input" id="name" type="text" autocomplete="off" />
            <input class="input" id="password" type="password" autocomplete="off" />
            <button class="btn" onclick="register()">Registrar</button>
            <button class="btn" onclick="panelInicio()">Volver</button>
        </div>
    `;
}
window.panelInicio = function(){
    document.querySelector('#app').innerHTML = `
    <div class="result" id="result">Please enter your name below 👇</div>
      <div class="input-box" id="input">
        <input class="input" id="name" type="text" autocomplete="off" />
        <input class="input" id="password" type="password" />
        <button class="btn" onclick="loggin()">Login</button>
        <button class="btn" onclick="panelRegister()">Registrar</button>
    </div>
`;   
}