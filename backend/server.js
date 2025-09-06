require("dotenv").config();

const express = require("express");
const app = express();
const path = require("path");
const cookieParser = require('cookie-parser');

const { logger, logEvents } = require("./middleware/logger");
const errorHandler = require("./middleware/errorHandler");

const cors = require("cors");
const connectDatabase = require("./config/database");

const mongoose = require("mongoose");
const cloudinary = require("cloudinary");
const http = require("http");
const server = http.createServer(app);

const PORT = process.env.PORT || 8000;

console.log(process.env.NODE_ENV);

connectDatabase();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

//middleware
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));
app.use(cookieParser());
app.use(logger);

app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:8081",
    ],
    methods: ["POST", "GET", "PUT", "DELETE"],
    credentials: true,
  })
);

app.use("/", express.static(path.join(__dirname, "public")));
app.use(errorHandler);

//routes
app.use("/", require("./routes/root"));
app.use("/auth", require("./routes/auth"));

//404 not found routes
app.all(/.*/, (req, res) => {
  res.status(404);
  if (req.accepts("html")) {    
    res.sendFile(path.join(__dirname, "views", "404.html"));
  } else if (req.accepts("json")) {
    res.json({ message: "404 Not Found" });
  } else {
    res.type("txt").send("404 Not Found");
  }
});

mongoose.connection.once("open", () => {
  console.log("Connected to MongoDB");
  server.listen(PORT, () =>
    console.log(
      `Server running on port ${PORT} in ${process.env.NODE_ENV} mode`
    )
  );
});

mongoose.connection.on("error", (err) => {
  console.log(err);
  logEvents(
    `${err.no}: ${err.code}\t${err.syscall}\t${err.hostname}`,
    "mongoErrLog.log"
  );
});