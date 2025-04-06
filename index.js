import express from "express"
import bcrypt from "bcryptjs"
import "dotenv/config"
import postgres from 'postgres'
import jwt from 'jsonwebtoken'
import cors from 'cors'

const sql = postgres({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_DB,
    username: process.env.DB_USER,
    password: process.env.DB_PASSWORD
})

const app=express()

app.use(express.json()) // Iulian: to make req.body actually work
app.use(cors())

app.get("/health", (req,res) => {
    // Iulian: simple health check to make sure it works
    res.sendStatus(200);
})

app.post("/user/register", async(req, res)=>{
    //getting the required data
    const mail=req.body.email
    const name=req.body.username
    const pass=req.body.password // Iulian: this needed to be password not pass

    //checking that the password is adequate
    // Iulian: this should be done via Regex
    const passRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/
    if (!pass.match(passRegex))  {
        res.status(400)
        res.send("Invalid password")
        return
    }
    //encrypt password
    const hashedPass = await bcrypt.hash(pass, 10); // Iulian: hashing is not done in-place
    //create the user, insert into database
    try {
        const task=await sql `insert into public.users (email, password, username) values (${mail}, ${hashedPass}, ${name})`
        res.status(200)
        res.send("The account was succesfully created. Please log in.")
    }
    catch (e) {
        // hopefully also deals with the case where the email already exists
        // Iulian: you don't technically know this is 409. you just know you caught an error. could be anything
        if(e.routine="_bt_check_unique"){
            res.status(409) 
            res.send("Invalid request. The email already exists.")
            return
        }
        // Iulian: else it was an unknown server error
        res.sendStatus(500)
    }
})

// Iulian: login route
app.post("/user/login", async (req, res)=>{
    // get required data
    const email = req.body.email
    const pass = req.body.password

    // try to find the user in the DB
    try{
        const userResponse = await sql`select * from public.users where email=${email}`
        const user = userResponse[0]
        
        // if the user doesn't exist
        if(user === undefined){
            res.status(403)
            res.send("Incorrect email or password.")
            return
        }

        const matches = await bcrypt.compare(pass, user.password)

        // if the password is wrong
        if(!matches){
            res.status(403)
            res.send("Incorrect email or password.")
            return
        }

        const token = jwt.sign({id: user.id}, process.env.JWT_SECRET, {expiresIn: "1h"})

        res.status(200).send(token)

    } catch (e) {
        console.log(e)
        res.sendStatus(500)
    }
})

// Iulian: JWT middleware. Should be used for everything below here
function checkJWT(req, res, next) {
    let token = req.headers["authorization"]

    if (token == null) return res.sendStatus(401)

    token = token.split(" ")[1]

    if(token == null) return res.sendStatus(401)

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.sendStatus(401)
        req.userID = decoded.id
        next()
    })
}

app.get("/user/me", checkJWT, async(req, res)=>{
const user=req.userID
try {
const task=await sql `select * from users where id=${user}`
const me=task[0]
res.status(200)
res.json({
"username": me.username,
"email": me.email,
"id": me.id
})
}
catch {
res.status(500)
res.send("Something went wrong!")
}
})

app.post("/group/create", checkJWT, async (req, res)=>{
    //we get the data we need
const name=req.body.groupName
const user=req.userID
var components="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
var code=""
for (var i=1; i<=8; i++) {
    var index=Math.floor(Math.random() *62)
    code+=components[index]
}
try {
const task=await sql`insert into public.groups (name, admin, code) values (${name}, ${user}, ${code}) returning id` // Iulian: returning must be mentioned
const request=await sql`insert into group_members (user_id, group_id) values (${user}, ${task[0].id})`
res.status(200)
res.send("The group has been created successfully.")
}
catch (e) {
    console.log(e)
    res.status(500)
    res.send("An unexpected error occured. Please try again.")
}
})

app.post("/group/join", checkJWT, async(req, res)=>{
    const user=req.userID
    const code=req.body.groupCode
    try {
         const groupIdRes=await sql`select id from public.groups where code=${code}`
         const groupIdObj=groupIdRes[0]
         if (!groupIdObj){
             res.status(404)
             res.send("This group does not exist.")
             return
         }
         const groupId = groupIdObj.id
         const bannedRes = await sql`select * from public.group_banned where group_id=${groupId} and user_id=${user}`;

         const banned=bannedRes[0]
         if (banned) {
             res.status(403)
             res.send("You have been banned for "+banned.reason+".")
             return
         }
         const existsRes=await sql`select * from public.group_members where user_id=${user} and group_id=${groupId}`
         const exists=existsRes[0]
         if (exists) {
             res.status(400)
             res.send("You have already joined this group")
             return
         }
         const task=await sql`insert into public.group_members (user_id, group_id) values (${user}, ${groupId})`
         res.status(200)
         res.send("You have successfully joined the group!")
    }
    catch (e) {
        console.log(e)
        res.status(500)
        res.send("Something went really, really wrong.")
    }
})

// implement the function that returns the join code for a given group
app.get("/group/code", checkJWT, async(req, res)=>{
const user=req.userID
const group=req.query.id
try {
const task=await sql`select * from groups where id=${group}`
const info=task[0]
if (info.admin!=user) {
res.status(403)
res.send("You are not an admin of this group.")
return
}
res.status(200)
res.send(info.code)
}
catch(e) {
res.status(500)
res.send("Unknown error.")
console.log(e)
} //end catch
})


//implement the function that returns the list of members of a given group
app.get("/group/members", checkJWT, async(req,res) => {
    const user = req.userID
    const group = req.query.id

    try{
      const memberInGroup = await sql`select * from group_members where user_id=${user} and group_id=${group}`

      if(memberInGroup[0] == undefined){
          res.status(403)
          res.send("You are not part of this group.")
          return
      }  
        
      const groupData = await sql`select admin from groups where id=${group}`

      if(groupData[0].admin == user){
          // if the user is the admin, we return list of names + IDs
          const members = await sql`select u.id as id, u.username as name from users u join group_members gm on u.id=gm.user_id where gm.group_id=${group}`
          res.status(200)
          res.json(members)
          return
      } 
      // else just names
      const members = await sql`select u.username as name from users u join group_members gm on u.id=gm.user_id where gm.group_id=${group}`
      res.status(200)
      res.json(members)
    } catch (e) {
        console.log(e)
        res.status(500)
        res.send("An unexpected error occured.")
    }
})

//implement the function that returns the list of banned members of a given group
app.get("/group/bannedMembers", checkJWT, async(req, res)=>{
const user=req.userID
const group=req.query.id
try {
const checkRes=await sql`select * from groups where id=${group}`
const check=checkRes[0]
if (check.admin!=user) {
res.status(403)
res.send("You are not authorized to see this information.")
return
}
const task=await sql`select u.id as id, u.username as name from users u join group_banned gb on u.id=gb.user_id where group_id=${group}`
res.status(200);
res.json(task)
}
catch {
res.status(500)
res.send("An unknown error has occured.")
console.log(e)
}
})

app.post("/group/ban", checkJWT, async(req, res)=>{
const user=req.userID
const tbbUser=req.body.userID
const group=req.body.groupID
const reason=req.body.reason
try {
const adminRes=await sql`select * from public.groups where id=${group} and admin=${user}`
const admin=adminRes[0]
if (!admin) {
res.status(403)
res.send("Error! You are not an admin.")
return
}
const userRes=await sql`select * from users where id=${tbbUser}`
const check=userRes[0]
if (!check) {
res.status(404)
res.send("The user cannot be found.")
return
}
const task=await sql`delete from group_members where user_id=${tbbUser} and group_id=${group}`
const ban=await sql`insert into group_banned (user_id, group_id, reason) values (${tbbUser}, ${group}, ${reason})`
res.status(200)
res.send("The user has been banned.")
}
catch {
res.status(500)
res.send("Something went wrong.")
}
})

app.get("/group/list", checkJWT, async(req, res)=>{
const user=req.userID
try {
// gm.user -> gm.user_id
const query = await sql`SELECT g.name as group_name, g.id as group_id, u.username as group_owner FROM groups g JOIN group_members gm ON g.id = gm.group_id JOIN users u ON g.admin=u.id WHERE gm.user_id=${user} ORDER BY g.id desc`
res.status(200)
res.json(query)
}
catch(e){
res.status(500)
res.send("Uh oh. Told you it wouldn't work.")
console.log(e)
}})

app.post("/group/unban", checkJWT, async(req, res)=>{
const user=req.userID
const group=req.body.groupID
const unbanUsr=req.body.id
try {
const checkRes=await sql`select * from groups where id=${group}`
const check=checkRes[0]
if (check.admin!=user) {
res.status(403)
res.send("You are not authorized to do this.")
return
}
const task=await sql`delete from group_banned where user_id=${unbanUsr}`
res.status(200)
res.send("The user has been unbanned successfully. They may now rejoin the group again if they wish.")
}
catch(e) {
res.status(500)
res.send("An unknown error has occured.")
console.log(e)
}
})


//here come the functions that manage activities (events)
app.post("/activity/create", checkJWT, async(req, res)=>{
const group=req.body.groupID
const name=req.body.name
const time=req.body.time
const location=req.body.location
const details=req.body.details
const user=req.userID
try {
const checkRes=await sql`select * from groups where id=${group}`
const check=checkRes[0]
if (!check) {
res.status(404)
res.send("Error: no group has been found.")
return
}
if (check.admin!=user) {
res.status(403)
res.send("You are not an admin of this group. You cannot create events.")
}
const create=await sql`insert into activities (name, time, location, details, group_id) values (${name}, ${time}, ${location}, ${details}, ${group})`
res.status(200)
res.send("The activity has been created successfully")
}
catch(e) {
res.status(500)
res.send("Unknown error")
console.log(e)
} //end catch
})

app.get("/activity/list", checkJWT, async(req, res)=>{
const user=req.userID
const group=req.query.groupID
try {
const checkRes=await sql`select * from group_members where user_id=${user} and group_id=${group}`
const check=checkRes[0]
if (check==undefined) {
res.status(403)
res.send("You are not a member of this group")
return
}
const task=await sql`select id, name, time, location, details from activities where group_id=${group} order by id desc`
res.status(200)
res.send(task)
}
catch(e) {
res.status(500)
res.send("An unknown error has occured")
console.log(e)
}
})

app.get("/group/admin", checkJWT, async(req, res)=>{
const user=req.userID
const group=req.query.groupID
try {
const task=await sql`select * from groups where id=${group}`
const check=task[0]
if (check.admin==user) {
res.status(200)
res.send("true")
}
else {
res.status(403)
res.send("false")
}
}
catch {
res.status(500)
res.send("Unknown error.")
}
})

app.post("/activity/delete", checkJWT, async(req, res)=>{
const user=req.userID
const act=req.body.activityID
const group=req.body.groupID
try {
const checkRes=await sql`select * from groups where id=${group}`
const check=checkRes[0]
if (check.admin!=user) {
res.status(403)
res.send("You are not an admin of this group.")
return
}
const task=await sql`delete from activities where id=${act}`
res.status(200)
res.send("The activity has been deleted successfully")
}
catch {
res.status(500)
res.send("An unknown error has occured.")
}
})

app.listen(process.env.PORT, ()=>{
    console.log("Server started on port "+process.env.PORT)
})
