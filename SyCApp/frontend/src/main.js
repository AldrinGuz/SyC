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
                            <button class="btn" onclick="data()">Datos</button>
                            <button class="btn" onclick="update()">Actualizar</button>
                            <button class="btn" onclick="logout()">Desconectar</button>
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
                    <button class="btn" onclick="data()">Datos</button>
                    <button class="btn" onclick="update()">Actualizar</button>
                    <button class="btn" onclick="logout()">Desconectar</button>
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
    document.getElementById("result").innerText = "Function"
}