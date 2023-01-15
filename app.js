require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS
const app = express();

const cors = require('cors');
app.use(cors());

//Config JSON Response
app.use(express.json());

//Models
const User = require('./models/User')

//Public Route
app.get('/', (req, res) => {
    res.status(200).json({ msg: "API Online" })
})


//Private Route
app.get("/user/:id", checkToken, async (req, res) => {
    const id = req.params.id

    //check if user exists
    const user = await User.findById(id, '-password')

    if(!user){
        return res.status(404).json({msg: "Usuário não encontrado."})
    }

    res.status(200).json({ user })
})

function checkToken(req, res, next) {

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        return res.status(401).json({msg: "Acesso negado"})
    }

    try {

        const secret = process.env.secret

        jwt.verify(token, secret)

      next()
    } catch(err) {
        res.status(400).json({msg: "Acesso negado, Verify"})
    }

}


//Register
app.post('/auth/register', async (req, res) => {

    const { name, email, password, confirmpassword } = req.body;

    //Validate
    if (!name) {
        return res.status(422).json({ msg: "Nome inválido ou vazio!" })
    }

    if (!email) {
        return res.status(422).json({ msg: "E-mail inválido ou vazio!" })
    }

    if (!password) {
        return res.status(422).json({ msg: "Senha inválida ou vazia!" })
    }

    if (!confirmpassword) {
        return res.status(422).json({ msg: "Confirmação de senha inválida ou vazia!" })
    }

    if (password !== confirmpassword) {
        return res.status(422).json({ msg: "As senhas não conferem!" })
    }

    //check if user exists

    const userExists = await User.findOne({ email: email })

    if (userExists) {
        return res.status(422).json({ msg: "Por favor, utilize outro e-mail!" })
    }

    //create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //create user
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {

        await user.save()
        res.status(201).json({ msg: "Usuário criado com sucesso." })

    } catch (error) {
        res.status(500).json({ msg: "Ocorreu um erro, tente mais tarde." })
    }

})

//login user
    app.post("/auth/login", async (req,res) => {

        const {email, password} = req.body

        //validations

        if(!email) {
            return res.status(422).json({msg: 'E-mail inválido ou vazio.'})
        }

        if(!password) {
            return res.status(422).json({msg: 'Senha inválida ou vazia.'})
        }

        //User exists?

        const user = await User.findOne({ email: email })

        if(!user) {
            return res.status(404).json({msg: 'Usuário não encontrado.'})
        }

        //check if password matches
        const checkPass = await bcrypt.compare(password, user.password)

        if(!checkPass) {
            return res.status(422).json({ msg: 'Senha inválida.' })
        }

        try {

            const secret = process.env.secret
            const token = jwt.sign(
                {
                id: user._id,
                },
                
                secret,
            )

            res.status(200).json({msg: 'Autenticação realizada com sucesso', token})

        } catch(err) {
            console.log(err)

            res.status(500).json({msg: 'Ocorreu um erro, tente mais tarde.'})
        }

    })


mongoose
    .connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.hwnukqn.mongodb.net/?retryWrites=true&w=majority`
    )
    .then(() => {
        app.listen(3000);
        console.log("Conectado")
    })
    .catch((err) => console.log(err))


