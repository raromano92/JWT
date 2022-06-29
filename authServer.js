require('dotenv').config()

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')

app.use(express.json())

/*========================================
        SERVER FOR REFRESH TOKENS
========================================*/

// REFRESH TOKENS USED TO INVALIDATE USERS WHO GAIN ACCESS WHO SHOULDN'T
// REFRESH TOKEN IS SAVED IN A SAFE SPOT, ACCESS TOKEN IS SET TO SHORT EXPIRATION
// STORE ALL AUTHENTICATION/AUTHORIZATION CODE HERE AWAY FROM MAIN SERVER.JS

// EMPTY ARRAY ACTING AS MOCK DB FOR DEMO ONLY, GOES TO DB NORMALLY
let refreshTokens = []

// USED TO CREATE A NEW TOKEN
app.post('/token', (req, res) => {
  // GRAB REFRESH TOKEN VIA REQ.BODY 
  const refreshToken = req.body.token
  // IF TOKEN IS NULL, RES WITH ERR
  if (refreshToken == null) return res.sendStatus(401)
  // DOES CURRENT REFRESH TOKENS INCLUDE REFRESH TOKEN THAT WAS SENT TO SERVER
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)
  // IF NOT, RES SEND 403 FORBIDDEN
  // ONCE TOKEN CLEARS, CHECK FOR VERIFICATION
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    // 403 IF VERIFY FAILS
    if (err) return res.sendStatus(403)
    // NOW CREATE ACCESS TOKEN
    const accessToken = generateAccessToken({ name: user.name })
    // RETURN ACCESS TOKEN VIA JSON
    res.json({ accessToken: accessToken })
  })
})

// FUNCTION TO DELETE REFRESH TOKENS, AS OF NOW USERS CAN GENERATE ACCESS TOKENS INFINITELY
app.delete('/logout', (req, res) => {
  // CHECK TO MAKE SURE TOKEN IN "ARRAY"(DB) IS NOT EQUAL TO REQ.BODY.TOKEN WERE PASSING TO DB
  refreshTokens = refreshTokens.filter(token => token !== req.body.token)
  // CONFIRM DELETION RES
  res.sendStatus(204)
})

app.post('/login', (req, res) => {
  // Authenticate User

  const username = req.body.username
  const user = { name: username }

  // CALLING TOKEN GENERATE FUNCTION 
  const accessToken = generateAccessToken(user)
  // REFRESH TOKEN CREATION, SAME USER SHOULD BE PASSED FOR BOTH TOKENS. REF SECRET USED FOR SERIALIZATION ON USER
  // EXPIRATION OF REFRESH TOKENS SHOULD BE HANDLED MANUALLY, NOT BY JWT
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
  // PUSH TOKEN TO DB UPON CREATION
  refreshTokens.push(refreshToken)
  // RETURN REFRESH TOKEN TO THE USER BELOW
  res.json({ accessToken: accessToken, refreshToken: refreshToken })
})

// THIS FUNCTION WILL GENERATE A TOKEN, THEN PASS IT TO USER (set expiry to 10-15 min generally)
function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s' })
}

app.listen(4000)