import express, { Request, RequestHandler } from "express";
import { PrismaClient, User } from "@prisma/client";
import bcrypt from "bcrypt";
import { v4 } from "uuid";
import cookieParser from "cookie-parser";

const client = new PrismaClient();
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set("view engine", "ejs");
app.use(express.static("public"));

type RequestWithUser = Request & { user?: User }


const authenticateMiddleware: RequestHandler = async (req: RequestWithUser, res, next) => {
  console.log(req.cookies);
  if (req.cookies["session-token"]) {
    const session = await client.session.findFirst({
      where: {
        token: req.cookies["session-token"],
      },
      include: {
        user: true
      }
    });
    if (session) {
      req.user = session.user;
    }
  }
  next();
}

app.use(authenticateMiddleware);

type UsersPostBody = {
  email: string,
  password: string,
  firstName: string,
  lastName: string,
}

app.post('/users', async (req, res) => {
  console.log(req.body);
  const {email, password, firstName, lastName} = req.body as UsersPostBody;
  const user = await client.user.create({
    data: {
      firstName,
      lastName,
      email,
      passwordHash: await bcrypt.hash(password, 10),
      sessions: {
        create: [
          {token: v4()}
        ]
      }
    },
    include: {
      sessions: true
    }
  });
  res.cookie('session-token', user.sessions[0].token)
  res.redirect('/home');
});

app.get("/signup", (req, res) => {
  res.render("pages/signup");
})

app.get("/signin", (req, res) => {
  res.render("pages/signin");
})

app.post('/sessions', async (req, res) => {
  const {email, password} = req.body as UsersPostBody;

  const user = await client.user.findFirst({
    where: {
      email,
    }
  })
  if (!user) {
    res.status(404).send("not found");
    return;
  }

  const isValid = bcrypt.compare(password, user.passwordHash);
  if (!isValid) {
    res.status(404).send("not found");
    return;
  }

  const session = await client.session.create({
    data: {
      token: v4(),
      userId: user.id
    }
  });

  res.cookie('session-token', session.token);
  res.redirect('/home');
});

app.get("/signout", async (req: RequestWithUser, res) => {
  if (req.user) {
    await client.session.deleteMany({
      where: {
        userId: req.user.id,
      }
    });
    res.clearCookie("session-token");
  }
  res.redirect("/");
})

app.get("/", (req: RequestWithUser, res) => {
  if (req.user) {
    res.redirect('/home');
  } else {
    res.render('pages/index');
  }
});

app.get("/home", (req: RequestWithUser, res) => {
  if (!req.user) {
    res.redirect("/");
  } else {
    res.render("pages/home", {
      name: `${req.user.firstName} ${req.user.lastName}`
    });
  }
});

app.post("/me", async (req: RequestWithUser, res) => {
  const {email, password} = req.body as UsersPostBody;
  if (!req.user) {
    res.redirect("/")
  } else {
    await client.user.update({
      where: {
        id: req.user.id,
      },
      data: {
        email,
        passwordHash: await bcrypt.hash(password, 10)
      }
    });

    await client.session.deleteMany({
      where: {
        userId: req.user.id,
      }
    });

    res.clearCookie("session-token");
    res.redirect("/");
  }
});

app.listen(3000, () => {
  console.log("I got started!");
});
