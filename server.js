require('dotenv').config()

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')

app.use(express.json())

const posts = [
  {
    username: 'Kyle',
    title: 'Post 1'
  },
  {
    username: 'Jim',
    title: 'Post 2'
  }
]

app.get('/posts', authenticateToken, (req, res) => {
  // GET ONLY POSTS USER HAS ACCESS TOO, AFTER JWT VERIFICATION
  res.json(posts.filter(post => post.username === req.user.name))
  
})

app.post('/login', (req, res) => {
  // AUTHENTICATE USER FIRST NORMALLY HERE, BEFORE JWT PROCESS

  // GET THE USERNAME
  const username = req.body.username
  // CREATE THE USER OBJECT
  const user = { name: username }
  // TAKES OUR PAYLOAD AND SERIALIZES THE USER OBJECT USING .ENV SECRET, ADD EXP DATE HERE IF NEC.
  const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET)
  // PASS DOWN ACCESS TOKEN AS JSON, TOKEN WITH USER INFO IS CREATED UPON LOGIN REQUEST
  res.json({ accessToken: accessToken})
})

// FUNCTION TO GET TOKEN USER SENDS US, VERIFY CORRECT USER, RETURN USER TO POST ROUTE
function authenticateToken(req, res, next) {
  // GET AUTHORIZATION HEADER FROM JWT
  const authHeader = req.headers['authorization']
  // IF THERE IS AN AUTHHEADER, THEN RETURN AUTHHEADER TOKEN PORTION THAT WAS SPLIT ON SPACE BETWEEN "BEARER TOKEN"
  const token = authHeader && authHeader.split(' ')[1]
  // IF NO TOKEN, IT WILL COME BACK UNDEFINED THEN WE SEND USER ERROR
  if (token == null) return res.sendStatus(401)
  // ONCE WE HAVE VALID TOKEN, VERIFY THE TOKEN. PASS IT TOKEN AND SECRET
  // CALLBACK TAKES AN ERR AND SERIALIZED OBJECT ("USER" IN THIS CASE)
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    // IF VERIFY FAILS, SEND ERR TO USER
    if (err) return res.sendStatus(403)
    // NOW WE HAVE VALID TOKEN, SET USER ON OUR REQUEST
    req.user = user
    console.log(user)
    // CALL NEXT TO MOVE ON FROM MIDDLEWARE
    next()

  })
}

app.listen(3000)