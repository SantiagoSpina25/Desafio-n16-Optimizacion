import mongoose from "mongoose";
import config from "../../config.js"

mongoose.set("strictQuery", false);

mongoose.connect(config.mongodb.cnxStr, config.mongodb.options)

class ContenedorMongoDb {

    constructor(nombreColeccion, esquema) {
        this.coleccion = mongoose.model(nombreColeccion, esquema)
    }


    async listar(username) {
        const readItem = await this.coleccion.find({ "username": username })
        return readItem
    }

    async listarAll() {
        const readItems = await this.coleccion.find()
        return readItems
    }

    async guardar(nuevoItem) {
        const saveItem = this.coleccion(nuevoItem)
        await saveItem.save()
    }

    async actualizar(id, nuevoItem) {
        const updateItem = await this.coleccion.replaceOne({"username": username},{$set: {nuevoItem}})
        return updateItem
    }

    async borrar(id) {
        await this.coleccion.deleteOne({"username": username})
    }


}

export default ContenedorMongoDb
