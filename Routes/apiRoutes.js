import express from "express";
import con from "../config/db.js";
import jwt from "jsonwebtoken";
import bcrypt from 'bcryptjs';

const router = express.Router();

const JWT_SECRET_KEY = 'your_jwt_secret_key';
const TOKEN_EXPIRATION_DAYS = 60;

const verifyToken = (req, res, next) => {
   let token = req.headers["authorization"];

   if (token && token.startsWith("Bearer ")) {
      token = token.split(" ")[1];
   } else {
      token = req.headers["token"];
   }

   if (!token) {
      return res.status(401).json({ success: false, message: "Token not provided" });
   }

   jwt.verify(token, JWT_SECRET_KEY, (err, decoded) => {
      if (err) {
         if (err.name === "TokenExpiredError") {
            return res.status(401).json({ success: false, message: "Token has expired" });
         }
         return res.status(401).json({ success: false, message: "Invalid token" });
      }
      req.user = decoded;
      next();
   });
};

//Registration
router.post('/register', async (req, res) => {
   const { name, phone, email, password } = req.body;

   if (!name || !phone || !email || !password) {
      return res.status(400).json({ status: false, message: 'All fields are required!' });
   }

   try {
      const [phoneCheckResult] = await con.query('SELECT phone FROM registration WHERE phone = ?', [phone]);

      if (phoneCheckResult.length > 0) {
         return res.status(400).json({
            status: false,
            message: `Phone number ${phone} is already registered`
         });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const insertQuery = `
         INSERT INTO registration (name, email, phone, password)
         VALUES (?, ?, ?, ?)
      `;
      const [insertResult] = await con.query(insertQuery, [name, email, phone, hashedPassword]);

      const insertUserQuery = `
         INSERT INTO users (phone, password)
         VALUES (?, ?)
      `;
      const [userResult] = await con.query(insertUserQuery, [phone, hashedPassword]);

      res.status(200).json({
         status: true,
         message: `User registered successfully with phone number ${phone}!`,
         id: insertResult.insertId
      });
   } catch (error) {
      console.error("Server error:", error);
      res.status(500).json({ status: false, message: 'Something went wrong' });
   }
});

//Authenticate
router.post("/authenticate", async (req, res) => {
   try {
      const { phone, password } = req.body;

      if (!phone || !password) {
         return res.status(400).json({
            status: false,
            message: "Phone and Password are required.",
         });
      }

      const query = `
       SELECT users.*, registration.name,registration.email
       FROM users
       INNER JOIN registration ON users.phone = registration.phone
       WHERE users.phone = ?
     `;
      const [results] = await con.query(query, [phone]);

      if (results.length === 0) {
         return res.status(401).json({
            status: false,
            message: "Invalid phone or password.",
         });
      }

      const user = results[0];

      const isPasswordMatch = await bcrypt.compare(password, user.password);
      if (!isPasswordMatch) {
         return res.status(401).json({
            status: false,
            message: "Invalid phone or password.",
         });
      }

      const token = jwt.sign({ id: user.id, phone: user.phone }, JWT_SECRET_KEY, {
         expiresIn: `${TOKEN_EXPIRATION_DAYS * 24 * 60 * 60}s`,
      });

      const tokenExpiredOn = new Date();
      tokenExpiredOn.setDate(tokenExpiredOn.getDate() + TOKEN_EXPIRATION_DAYS);

      await con.query("UPDATE users SET token = ? WHERE id = ?", [token, user.id]);

      return res.status(200).json({
         status: true,
         message: "Login successfully.",
         data: {
            id: user.id,
            name: user.name,
            phone: user.phone,
            email: user.email,
            token,
            token_expired_on: tokenExpiredOn,
         },
      });

   } catch (error) {
      console.error("Error in login API:", error);
      return res.status(500).json({
         status: false,
         message: "Server error. Please try again later.",
      });
   }
});

//Forgot password
router.put("/forgot-password", verifyToken, async (req, res) => {
   const { phone } = req.query;
   const { new_password, confirm_password } = req.body;

   if (!phone || !new_password || !confirm_password) {
      return res.status(400).json({
         success: false,
         message: "Phone number, new password, and confirm password are required",
      });
   }

   if (new_password !== confirm_password) {
      return res.status(400).json({
         success: false,
         message: "New password and confirm password do not match",
      });
   }

   try {
      const hashedPassword = await bcrypt.hash(new_password, 10);

      const updateUserQuery = `UPDATE users SET password = ? WHERE phone = ?`;
      const updateRegistrationQuery = `UPDATE registration SET password = ? WHERE phone = ?`;

      const [userResult] = await con.query(updateUserQuery, [hashedPassword, phone]);
      const [registrationResult] = await con.query(updateRegistrationQuery, [hashedPassword, phone]);

      if (userResult.affectedRows === 0 && registrationResult.affectedRows === 0) {
         return res.status(404).json({
            success: false,
            message: "User not found with this phone number",
         });
      }

      return res.status(200).json({
         success: true,
         message: "Password updated successfully",
      });
   } catch (error) {
      console.error(error);
      return res.status(500).json({
         success: false,
         message: "An error occurred while updating the password",
      });
   }
});

router.get('/logout', (req, res) => {
   res.clearCookie('token');
   return res.json({ Status: true });
});

export { router as apiRoutes };