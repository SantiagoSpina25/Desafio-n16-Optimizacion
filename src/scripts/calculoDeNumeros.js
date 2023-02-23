
process.on("message", numeros =>{
    const resultado = {}
    for(let i = 0; i < numeros; i++){
        const random = Math.floor(Math.random() * 1000)
        if(!resultado[random]){
            resultado[random] = 0
        }
        resultado[random]++
    }
    process.send(resultado)
})

process.send("finalizado")