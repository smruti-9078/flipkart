import express from 'express'
import 'dotenv/config'
import connectDB from './database/db.js'
import userRoute from './routes/userRoute.js'

import productRouter from './routes/productRoute.js'
import cors from 'cors'


const app = express()
const PORT = process.env.PORT || 3000


app.use(express.json())


app.use(cors({
    origin:'http://localhost:5173',
    credentials:true

}))
app.use(express.urlencoded({ extended: true }));

app.use('/api/user',userRoute)

app.use('/api/product',productRouter)

// http://localhost:8000/api/user/register

app.listen(PORT,() => {
    connectDB()
    console.log(`Server is listening at port:${PORT}`)
})