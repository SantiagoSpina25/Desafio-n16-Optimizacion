
/*============================[Modulos]============================*/

import express from "express"
import session from "express-session"
import exphbs from 'express-handlebars'
import bcrypt from 'bcrypt'
import compression from "compression"

import cluster from "cluster"
import os from "os"
const CPU_CORES = os.cpus().length;


import dotenv from "dotenv"
dotenv.config()
import minimist from "minimist"

import { fork } from "child_process"

import passport from "passport"
import { Strategy } from "passport-local"
const LocalStrategy = Strategy


/*----------- Base de datos -----------*/

import ContenedorMongoDb from "./src/contenedores/ContenedorMongoDb.js"

const usuariosDb = new ContenedorMongoDb("usuarios", {
        username: { type: String, required: true },
        password: { type: String, required: true },
        email: { type: String, required: true }
})



/*----------- Socket.io -----------*/

import { Server as HttpServer } from 'http'
import { Server as IOServer } from 'socket.io'
import path from "path"


const app = express()

const httpServer = new HttpServer(app)
const io = new IOServer(httpServer)

io.on("connection", socket =>{
    console.log("Nuevo cliente conectado")
})



/*----------- Loggers -----------*/

import { logInfo, logWarn, logError } from "./src/loggers/index.js"




/*============================[Middlewares]============================*/

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(compression())


// Logging general
app.use((req,res,next)=>{
    logInfo(`${req.method} ${req.url}`)
    next()
})

// Logging rutas inexistentes

// app.use("*",(req,res,next)=>{
//     logWarn(`${req.method} ${req.originalUrl} -- Ruta inexistente`)
//     next()
// })



/*----------- Passport -----------*/

passport.use(new LocalStrategy(
    async function (username, password, done) {
        console.log(`${username} ${password}`)

        //Logica para validar si un usuario existe
        await usuariosDb.listar(username).then(data=>{

            const usuarioEncontrado = data.find(usuario=> usuario.username == username)

            if(usuarioEncontrado){
                const userPassword = usuarioEncontrado.password
                const match = verifyPass(userPassword, password)
    
                if (!match) {
                    return done(null, false)
                }
                return done(null, data);
            }
            else{
                console.log("Usuario no encontrado en la DB")
                return done(null, false);
            }
        })
    }
))

passport.serializeUser((user, done)=> {
    const usuario = user[0]
    done(null, usuario.username);
})
  
passport.deserializeUser((username, done)=> {
    usuariosDb.listar(username).then(data=>{
        const usuarioEncontrado = data.find(usuario=> usuario.username == username)
        done(null, usuarioEncontrado);
    })
})



/*----------- Session -----------*/
app.use(session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 600000 //10 min
    }
}))

app.use(passport.initialize())
app.use(passport.session())


// Metodos de Auth con Bcrypt
async function generateHashPassword(password) {
    const hashPassword = await bcrypt.hash(password, 10)
    return hashPassword
}

async function verifyPass(userPassword, password) {
    const match = await bcrypt.compare(password, userPassword)
    console.log(`pass login: ${password} || pass hash: ${userPassword}`)
    return match
}



function isAuth(req, res, next) {
    if (req.isAuthenticated()) {
        next()
    } else {
        res.redirect('/login')
    }
}


/*----------- Motor de plantillas -----------*/

app.set('views', 'src/views');
app.engine('.hbs', exphbs.engine({
    defaultLayout: 'main',
    layoutsDir: path.join(app.get('views'), 'layouts'),
    extname: '.hbs'
}));
app.set('view engine', '.hbs');






/*============================[Rutas]============================*/


app.get('/', (req, res) => {
    res.redirect('/login')
})


app.get('/login', (req, res) => {
    res.render('login.hbs');
})


app.get('/register', (req, res) => {
    res.render('registro.hbs');
})


app.post('/login', passport.authenticate('local', { successRedirect: '/datos', failureRedirect: '/login-error' }));






app.get('/datos', isAuth, (req, res) => {
    if (!req.user.contador) {
        req.user.contador = 1
    } else {
        req.user.contador++
    }
    const datosUsuario = {
        nombre: req.user.username,
        email: req.user.email
    }
    res.render('datos', { contador: req.user.contador, datos: datosUsuario });
})




app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    const newUser = { username: username, password: await generateHashPassword(password), email: email }

    await usuariosDb.listar(username).then(data=>{
        
        const usuarioEncontrado = data.find(usuario=> usuario.username == username)

        if(usuarioEncontrado){
            console.log("Usuario ya existente")
            res.redirect("/register-error")
        }else{
            console.log("Nuevo usuario creado")
            usuariosDb.guardar(newUser)
            res.redirect('/login')
        }

        
    })


})



app.get('/logout', (req, res) => {
    req.logOut(err => {
        res.redirect('/');
    });
})


app.get('/login-error', (req, res) => {
    res.render('login-error');
})

app.get('/register-error', (req, res) => {
    res.render('registro-error');
})




app.get('/info', (req, res) => {

    const info = {
        processId : process.pid,
        versionNode : process.version,
        plataforma: process.platform,
        usoDeMemoria: process.memoryUsage().rss,
        directorioActual: process.argv,
        carpetaProyecto: process.cwd(),
        cpuCores: CPU_CORES
    }
    console.log(info)
    res.render('info', { info: info });
})


function calcular(numero){
    return new Promise((res,rej)=>{
        const forkedProcess = fork('./src/scripts/calculoDeNumeros.js')
        forkedProcess.on("message", (msg)=>{
            if(msg == "finalizado"){
                forkedProcess.send(numero)
            }
            else{
                res(msg)
            }
        })
    })
}



app.get('/randoms', async (req,res) => {
    
    const { numeros = 100000000 } = req.query
    
    const resultado = await calcular(numeros)
    res.send(resultado)
})


app.get('/info-nginx', (req, res) => {
    res.send(`Server en puerto ${PORT} - PID ${process.pid} - ${new Date().toLocaleString()}`)
})

/*============================[Servidor]============================*/


/*----------- Minimist -----------*/
let options = { alias: { p: "port", m: "modo" }, default: { p: 8080, m: "fork" } }

let args = minimist(process.argv.slice(2), options)
const PORT = args.port
const modo = args.modo



const server = httpServer.listen(PORT, () => {
    console.log(`Server en puerto ${PORT} - PID ${process.pid} - Modo: ${modo}`)
    })
    server.on('error', error => {
    console.error(`Error en el servidor ${error}`);
});