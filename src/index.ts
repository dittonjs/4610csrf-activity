import express from "express";
import { PrismaClient } from "@prisma/client";

const client = new PrismaClient();
const app = express();
app.use(express.json());

app.post('/users', async (req, res) => {
  const user = await client.user.create({
    data: {
      firstName: "Joseph",
      lastName: "Ditton",
      email: "joseph.ditton@usu.edu",
      passwordHash: "q23oejklnvzlskjfdnf"
    }
  });
  res.json({ user });
});

app.get("/users", async (req, res) => {
  const users = await client.user.findMany();
  res.json({ users });
})

app.get("/", (req, res) => {
  res.send(`<h1>Hello, world!</h1>`);
});

app.listen(3000, () => {
  console.log("I got started!");
});