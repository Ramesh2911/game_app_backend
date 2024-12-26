import express from "express";
import con from "../config/db.js";
import jwt from "jsonwebtoken";
import bcrypt from 'bcryptjs';
import moment from "moment-timezone";
import multer from "multer";
import path from "path";
import { fileURLToPath } from 'url';
import fs from 'fs';

const router = express.Router();

const JWT_SECRET_KEY = 'your_jwt_secret_key';
const TOKEN_EXPIRATION_DAYS = 60;
const timezone = 'Asia/Kolkata';
const BASE_URL = "http://127.0.0.1:3000/uploads";
//const BASE_URL = "http://bet21.co.in/uploads";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadDir = path.join(__dirname, '../uploads');

if (!fs.existsSync(uploadDir)) {
   fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
   destination: (req, file, cb) => {
      cb(null, uploadDir);
   },
   filename: (req, file, cb) => {
      cb(null, `${Date.now()}-${file.originalname}`);
   },
});

const upload = multer({ storage: storage });

const formatDateForDatabase = (date) => {
   const d = new Date(date);
   const year = d.getFullYear();
   const month = String(d.getMonth() + 1).padStart(2, '0');
   const day = String(d.getDate()).padStart(2, '0');
   const hours = String(d.getHours()).padStart(2, '0');
   const minutes = String(d.getMinutes()).padStart(2, '0');
   const seconds = String(d.getSeconds()).padStart(2, '0');
   return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
};

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

//User Registration
router.post('/register', async (req, res) => {
   const { name, phone, email, password } = req.body;

   if (!name || !phone || !email || !password) {
      return res.status(400).json({ status: false, message: 'All fields are required!' });
   }

   const cleanedPhone = phone.replace(/\D/g, '');

   const phoneRegex = /^[0-9]{10,15}$/;
   if (!phoneRegex.test(cleanedPhone)) {
      return res.status(400).json({
         status: false,
         message: 'Phone number must be between 10 to 15 digits!'
      });
   }

   const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
   if (!emailRegex.test(email)) {
      return res.status(400).json({
         status: false,
         message: 'Invalid email format. Please provide a valid email address.'
      });
   }

   try {
      const [phoneCheckResult] = await con.query('SELECT phone FROM users WHERE phone = ?', [phone]);

      if (phoneCheckResult.length > 0) {
         return res.status(400).json({
            status: false,
            message: `Phone number ${phone} is already registered`
         });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const insertQuery = `
         INSERT INTO users (name, email, phone, password, app_id, is_active)
         VALUES (?, ?, ?, ?, 1, 1)
      `;
      const [insertResult] = await con.query(insertQuery, [name, email, phone, hashedPassword]);

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

//Admin Registration
router.post('/admin-register', async (req, res) => {
   const { name, phone, email, password } = req.body;

   if (!name || !phone || !email || !password) {
      return res.status(400).json({ status: false, message: 'All fields are required!' });
   }

   const cleanedPhone = phone.replace(/\D/g, '');

   const phoneRegex = /^[0-9]{10,15}$/;
   if (!phoneRegex.test(cleanedPhone)) {
      return res.status(400).json({
         status: false,
         message: 'Phone number must be between 10 to 15 digits!'
      });
   }

   const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
   if (!emailRegex.test(email)) {
      return res.status(400).json({
         status: false,
         message: 'Invalid email format. Please provide a valid email address.'
      });
   }

   try {
      const [phoneCheckResult] = await con.query('SELECT phone FROM app_admin_master WHERE phone = ?', [phone]);

      if (phoneCheckResult.length > 0) {
         return res.status(400).json({
            status: false,
            message: `Phone number ${phone} is already registered`
         });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const insertQuery = `
      INSERT INTO app_admin_master (
       app_id, name, email, phone, password, is_locked, is_active,last_login_date,created_by,modified_by, created_at, updated_at
      ) VALUES (1,?, ?, ?, ?, 0, 1,NULL,1,1, NOW(), NOW())
   `;
      const [insertResult] = await con.query(insertQuery, [name, email, phone, hashedPassword]);

      res.status(200).json({
         status: true,
         message: `Admin registered successfully with phone number ${phone} and ${email}!`,
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

      const query = `SELECT * FROM users WHERE phone = ?`;
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

      const token = jwt.sign({ id: user.user_id, phone: user.phone }, JWT_SECRET_KEY, {
         expiresIn: `${TOKEN_EXPIRATION_DAYS * 24 * 60 * 60}s`,
      });

      const decodedToken = jwt.decode(token);
      const tokenExpiredOn = new Date(decodedToken.exp * 1000);

      await con.query("UPDATE users SET token = ? WHERE user_id = ?", [token, user.user_id]);

      return res.status(200).json({
         status: true,
         message: "Login successfully.",
         data: {
            id: user.user_id,
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

//Admin Authenticate
router.post("/admin-authenticate", async (req, res) => {
   try {
      const { phone, password } = req.body;

      if (!phone || !password) {
         return res.status(400).json({
            status: false,
            message: "Phone and Password are required.",
         });
      }

      const query = `SELECT * FROM app_admin_master WHERE phone = ?`;
      const [results] = await con.query(query, [phone]);

      if (results.length === 0) {
         return res.status(401).json({
            status: false,
            message: "Invalid phone or password.",
         });
      }

      const user = results[0];

      const isPasswordMatch = await bcrypt.compare(password, user.Password);
      if (!isPasswordMatch) {
         return res.status(401).json({
            status: false,
            message: "Invalid phone or password.",
         });
      }

      const token = jwt.sign({ id: user.admin_id, phone: user.phone }, JWT_SECRET_KEY, {
         expiresIn: `${TOKEN_EXPIRATION_DAYS * 24 * 60 * 60}s`,
      });

      const decodedToken = jwt.decode(token);
      const tokenExpiredOn = new Date(decodedToken.exp * 1000);

      await con.query("UPDATE app_admin_master SET token = ? WHERE admin_id = ?", [token, user.admin_id]);

      return res.status(200).json({
         status: true,
         message: "Login successfully.",
         data: {
            id: user.admin_id,
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

//Version Check
router.post('/version-check', async (req, res) => {
   const { version_code, client_type, device_info, fcm_token } = req.headers;

   if (!version_code || !client_type || !device_info || !fcm_token) {
      return res.status(400).json({
         status: false,
         message: 'Missing required headers: version_code, client_type, device_info, or fcm_token',
      });
   }

   try {
      const clientTypes = client_type === 'ALL' ? ['IOS', 'ANDROID', 'WEB'] : [client_type];

      const versionQuery = `
         SELECT version_code, version_name, update_note, update_date, app_url, is_mandatory
         FROM app_version
         WHERE client_type IN (?) AND is_active = 1
         ORDER BY id DESC
         LIMIT 1
      `;
      const [versionResult] = await con.query(versionQuery, [clientTypes]);

      if (!versionResult || versionResult.length === 0) {
         return res.status(404).json({
            status: false,
            message: 'No active version found for the specified client type(s)',
         });
      }

      const formattedUpdateDate = moment(versionResult[0].update_date)
         .tz(timezone)
         .format('YYYY-MM-DD HH:mm:ss');

      const configQuery = `
         SELECT id, config_key, value, client_type, is_active
         FROM app_configuration
         WHERE client_type IN (?) AND is_active = 1
      `;
      const [configResult] = await con.query(configQuery, [clientTypes]);

      res.status(200).json({
         status: true,
         message: 'Validated successfully',
         version_info: {
            version_code: versionResult[0].version_code,
            version_name: versionResult[0].version_name,
            update_note: versionResult[0].update_note,
            update_date: formattedUpdateDate,
            app_url: versionResult[0].app_url,
            is_mandatory: versionResult[0].is_mandatory,
         },
         config_info: configResult.length > 0
            ? configResult.map((config) => ({
               id: config.id,
               config_key: config.config_key,
               value: config.value,
               client_type: config.client_type,
               is_active: config.is_active,
            }))
            : [],
      });
   } catch (error) {
      console.error('Error occurred:', error);
      res.status(500).json({
         status: false,
         message: 'Internal server error',
         error: error.message,
      });
   }
});

//User Info
router.post('/user-info', async (req, res) => {
   const {
      version_code,
      client_type,
      device_info,
      fcm_token,
      login,
      access_token,
   } = req.headers;

   if (!version_code || !client_type || !device_info || !fcm_token || !login || !access_token) {
      return res.status(400).json({
         status: false,
         message: "Missing required headers: 'login' and/or 'access_token'.",
      });
   }

   try {
      const decoded = jwt.verify(access_token, JWT_SECRET_KEY);
      if (!decoded) {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      const tokenQuery = `
         SELECT token FROM users WHERE phone = ?;
      `;
      const [tokenResult] = await con.query(tokenQuery, [login]);

      if (tokenResult.length === 0 || tokenResult[0].token !== access_token) {
         return res.status(401).json({
            status: false,
            message: 'Access token mismatch or user not found.',
         });
      }

      const userInfoQuery = `
         SELECT
            user_id AS user_id,
            name,
            email,
            phone
         FROM
            users
         WHERE
            phone = ?;
      `;

      const [userResults] = await con.query(userInfoQuery, [login]);

      if (userResults.length === 0) {
         return res.status(404).json({
            status: false,
            message: 'User not found.',
         });
      }

      const user = userResults[0];

      const withdrawalQuery = `
      SELECT
      bank_id,
         account_holder_name,
         account_number,
         ifsc_code,
         paytm_number,
         upi_address
      FROM
         user_bank_info
      WHERE
         user_id = ?
   `;

      const [withdrawalResults] = await con.query(withdrawalQuery, [user.user_id]);

      const responseData = {
         id: user.user_id,
         name: user.name,
         email: user.email,
         phone: user.phone,
         ...(withdrawalResults.length > 0 ? withdrawalResults[0] : {}),
      };

      return res.status(200).json({
         status: true,
         message: 'User details fetched successfully.',
         data: responseData,
      });
   } catch (error) {
      if (error.name === 'JsonWebTokenError') {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      console.error(error);
      return res.status(500).json({
         status: false,
         message: 'Internal server error.',
      });
   }
});

//Game list
// router.post('/game-list', async (req, res) => {
//    const { user_id, type } = req.body;
//    const {
//       version_code,
//       client_type,
//       device_info,
//       fcm_token,
//       login,
//       access_token,
//    } = req.headers;

//    if (!type || !['USER', 'ADMIN'].includes(type)) {
//       return res.status(400).json({
//          status: false,
//          message: 'Invalid or missing type field. Allowed values are "USER" or "ADMIN".',
//       });
//    }

//    if (type === 'USER') {
//       if (
//          !version_code ||
//          !client_type ||
//          !device_info ||
//          !fcm_token ||
//          !login ||
//          !access_token ||
//          !user_id
//       ) {
//          return res.status(400).json({
//             status: false,
//             message: 'Missing required fields for USER login.',
//          });
//       }
//    } else if (type === 'ADMIN') {
//       if (!login || !access_token) {
//          return res.status(400).json({
//             status: false,
//             message: 'Missing required fields for ADMIN login (login and access_token).',
//          });
//       }
//    }

//    try {
//       const decoded = jwt.verify(access_token, JWT_SECRET_KEY);
//       if (!decoded) {
//          return res.status(401).json({
//             status: false,
//             message: 'Invalid or expired access token.',
//          });
//       }

//       if (type === 'USER') {
//          const tokenQuery = `
//             SELECT user_id, token
//             FROM users
//             WHERE phone = ?;
//          `;
//          const [tokenResult] = await con.execute(tokenQuery, [login]);

//          if (tokenResult.length === 0 || tokenResult[0].token !== access_token) {
//             return res.status(401).json({
//                status: false,
//                message: 'Access token mismatch or user not found.',
//             });
//          }

//          if (tokenResult[0].user_id !== parseInt(user_id, 10)) {
//             return res.status(403).json({
//                status: false,
//                message: 'User ID does not match the authenticated user.',
//             });
//          }
//       }

//       if (type === 'ADMIN') {
//          const adminQuery = `
//             SELECT admin_id, token
//             FROM app_admin_master
//             WHERE phone = ?;
//          `;
//          const [adminResult] = await con.execute(adminQuery, [login]);

//          if (adminResult.length === 0 || adminResult[0].token !== access_token) {
//             return res.status(401).json({
//                status: false,
//                message: 'Access token mismatch or admin not found.',
//             });
//          }
//       }

//       const gameQuery = `
//          SELECT game_id, app_id, game_name, game_pic, is_active
//          FROM game_master
//          WHERE is_active = 1 AND is_deleted = 0;
//       `;
//       const [games] = await con.execute(gameQuery);

//       const currentTime = moment();

//       const gameList = await Promise.all(
//          games.map(async (game) => {
//             const slotQuery = `
//                SELECT COUNT(*) AS active_slots
//                FROM game_slot_configuration_master
//                WHERE game_id = ?
//                  AND is_active = 1
//                  AND is_deleted = 0
//                  AND ? BETWEEN start_time AND end_time;
//             `;
//             const [slotResults] = await con.execute(slotQuery, [
//                game.game_id,
//                currentTime.format('YYYY-MM-DD HH:mm:ss'),
//             ]);

//             const is_game_active = slotResults[0].active_slots > 0 ? 1 : 0;

//             return {
//                ...game,
//                is_game_active,
//             };
//          })
//       );

//       res.status(200).json({
//          status: true,
//          message: 'Game list retrieved successfully',
//          gameList,
//       });
//    } catch (err) {
//       console.error('Error:', err);
//       if (err.name === 'JsonWebTokenError') {
//          return res.status(401).json({
//             status: false,
//             message: 'Invalid or expired access token.',
//          });
//       }

//       res.status(500).json({
//          status: false,
//          message: 'Internal server error',
//       });
//    }
// });

router.post('/game-list', async (req, res) => {
   const { user_id, type } = req.body;
   const {
      version_code,
      client_type,
      device_info,
      fcm_token,
      login,
      access_token,
   } = req.headers;



   if (!type || !['USER', 'ADMIN'].includes(type)) {
      return res.status(400).json({
         status: false,
         message: 'Invalid or missing type field. Allowed values are "USER" or "ADMIN".',
      });
   }

   if (type === 'USER') {
      if (
         !version_code ||
         !client_type ||
         !device_info ||
         !fcm_token ||
         !login ||
         !access_token ||
         !user_id
      ) {
         return res.status(400).json({
            status: false,
            message: 'Missing required fields for USER login.',
         });
      }
   } else if (type === 'ADMIN') {
      if (!login || !access_token) {
         return res.status(400).json({
            status: false,
            message: 'Missing required fields for ADMIN login (login and access_token).',
         });
      }
   }

   try {
      const decoded = jwt.verify(access_token, JWT_SECRET_KEY);
      if (!decoded) {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      if (type === 'USER') {
         const tokenQuery = `
            SELECT user_id, token
            FROM users
            WHERE phone = ?;
         `;
         const [tokenResult] = await con.execute(tokenQuery, [login]);

         if (tokenResult.length === 0 || tokenResult[0].token !== access_token) {
            return res.status(401).json({
               status: false,
               message: 'Access token mismatch or user not found.',
            });
         }

         if (tokenResult[0].user_id !== parseInt(user_id, 10)) {
            return res.status(403).json({
               status: false,
               message: 'User ID does not match the authenticated user.',
            });
         }
      }

      if (type === 'ADMIN') {
         const adminQuery = `
            SELECT admin_id, token
            FROM app_admin_master
            WHERE phone = ?;
         `;
         const [adminResult] = await con.execute(adminQuery, [login]);

         if (adminResult.length === 0 || adminResult[0].token !== access_token) {
            return res.status(401).json({
               status: false,
               message: 'Access token mismatch or admin not found.',
            });
         }
      }

      const gameQuery = `
         SELECT game_id, app_id, game_name, game_pic, is_active
         FROM game_master
         WHERE is_active = 1 AND is_deleted = 0;
      `;
      const [games] = await con.execute(gameQuery);

      const currentTime = moment();

      const gameList = await Promise.all(
         games.map(async (game) => {
            const slotQuery = `
               SELECT COUNT(*) AS active_slots
               FROM game_slot_configuration_master
               WHERE game_id = ?
                 AND is_active = 1
                 AND is_deleted = 0
                 AND ? BETWEEN start_time AND end_time;
            `;
            const [slotResults] = await con.execute(slotQuery, [
               game.game_id,
               currentTime.format('YYYY-MM-DD HH:mm:ss'),
            ]);

            const is_game_active = slotResults[0].active_slots > 0 ? 1 : 0;

            return {
               ...game,
               game_pic: `${BASE_URL}/${game.game_pic}`,
               is_game_active,
            };
         })
      );

      res.status(200).json({
         status: true,
         message: 'Game list retrieved successfully',
         gameList,
      });
   } catch (err) {
      console.error('Error:', err);
      if (err.name === 'JsonWebTokenError') {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      res.status(500).json({
         status: false,
         message: 'Internal server error',
      });
   }
});

//Game type list
router.post('/game-type-list', async (req, res) => {
   const { game_id, type } = req.body;
   const {
      version_code,
      client_type,
      device_info,
      fcm_token,
      login,
      access_token,
   } = req.headers;

   if (!type || !['USER', 'ADMIN'].includes(type)) {
      return res.status(400).json({
         status: false,
         message: 'Invalid or missing type field. Allowed values are "USER" or "ADMIN".',
      });
   }

   if (type === 'USER') {
      if (
         !version_code ||
         !client_type ||
         !device_info ||
         !fcm_token ||
         !login ||
         !access_token ||
         !game_id
      ) {
         return res.status(400).json({
            status: false,
            message: 'Missing required fields for USER login.',
         });
      }
   } else if (type === 'ADMIN') {
      if (!login || !access_token || !game_id) {
         return res.status(400).json({
            status: false,
            message: 'Missing required fields for ADMIN login (login and access_token).',
         });
      }
   }

   try {
      const decoded = jwt.verify(access_token, JWT_SECRET_KEY);
      if (!decoded) {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      if (type === 'USER') {
         const tokenQuery = `
            SELECT user_id, token
            FROM users
            WHERE phone = ?;
         `;
         const [tokenResult] = await con.execute(tokenQuery, [login]);

         if (tokenResult.length === 0 || tokenResult[0].token !== access_token) {
            return res.status(401).json({
               status: false,
               message: 'Access token mismatch or user not found.',
            });
         }
      }

      if (type === 'ADMIN') {
         const adminQuery = `
            SELECT admin_id, token
            FROM app_admin_master
            WHERE phone = ?;
         `;
         const [adminResult] = await con.execute(adminQuery, [login]);

         if (adminResult.length === 0 || adminResult[0].token !== access_token) {
            return res.status(401).json({
               status: false,
               message: 'Access token mismatch or admin not found.',
            });
         }
      }

      const query = `
       SELECT game_type_id, game_type_name
       FROM game_type_master
       WHERE game_id = ?;
     `;
      const [gameTypeResults] = await con.execute(query, [game_id]);

      res.status(200).json({
         status: true,
         message: gameTypeResults.length > 0 ? 'Game type list retrieved successfully' : 'No game types found for the provided game_id.',
         gameTypeList: gameTypeResults || [],
      });
   } catch (err) {
      console.error('Error:', err);
      if (err.name === 'JsonWebTokenError') {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      res.status(500).json({
         status: false,
         message: 'Internal server error',
      });
   }
});

//Game details
router.post('/game-details', async (req, res) => {
   const { game_id, game_type_id } = req.body;
   const {
      version_code,
      client_type,
      device_info,
      fcm_token,
      login,
      access_token,
   } = req.headers;

   if (
      !version_code ||
      !client_type ||
      !device_info ||
      !fcm_token ||
      !login ||
      !access_token
   ) {
      return res.status(400).json({
         status: false,
         message: 'Missing required headers',
      });
   }

   if (!game_id || !game_type_id) {
      return res.status(400).json({
         status: false,
         message: 'Missing required body parameters: game_id or game_type_id',
      });
   }

   try {
      const decoded = jwt.verify(access_token, JWT_SECRET_KEY);
      if (!decoded) {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      const tokenQuery = `
         SELECT user_id, token
         FROM users
         WHERE phone = ?;
      `;
      const [tokenResult] = await con.execute(tokenQuery, [login]);

      if (tokenResult.length === 0 || tokenResult[0].token !== access_token) {
         return res.status(401).json({
            status: false,
            message: 'Access token mismatch or user not found.',
         });
      }

      const gameQuery = `
         SELECT Game_id AS game_id, Game_name AS game_name, Game_pic AS game_pic
         FROM game_master
         WHERE Game_id = ? AND is_active = 1;
      `;
      const [gameResults] = await con.execute(gameQuery, [game_id]);

      if (gameResults.length === 0) {
         return res.status(400).json({
            status: false,
            message: 'Game not found or inactive.',
         });
      }
      const gameDetails = gameResults[0];

      const gameTypeQuery = `
         SELECT
            game_type_id AS game_type_id,
            game_type_name AS game_type_name,
            noOf_item_choose AS game_max_digit_allowed,
            min_entry_fee AS game_min_play_amount,
            max_entry_fee AS game_max_play_amount,
            prize_value_noOf_times AS prize_value,
            is_active
         FROM game_type_master
         WHERE game_id = ? AND game_type_id = ? AND is_active = 1;
      `;
      const [gameTypeResults] = await con.execute(gameTypeQuery, [game_id, game_type_id]);

      if (gameTypeResults.length === 0) {
         return res.status(400).json({
            status: false,
            message: 'Game type not found or inactive.',
         });
      }
      const gameTypeDetails = gameTypeResults[0];

      const slotQuery = `
       SELECT * FROM game_slot_configuration_master WHERE game_id = ? AND game_type_id = ? AND is_active = 1 AND game_slot_configuration_master.start_time <=(NOW()) AND game_slot_configuration_master.end_time >=(NOW());
      `;

      const [slotResults] = await con.execute(slotQuery, [game_id, game_type_id]);

      const is_game_active = slotResults.length > 0 ? 1 : 0;

      const activeSlot = slotResults.length > 0 ? slotResults[0] : null;

      if (activeSlot) {
         const currentTime = new Date();
         const endTimeString = activeSlot.end_time;
         const currentDate = currentTime.toISOString().split('T')[0];
         const endTime = new Date(`${currentDate}T${endTimeString}`);

         const timeRemaining = endTime - currentTime;
         const secondsRemaining = timeRemaining > 0 ? Math.floor(timeRemaining / 1000) : 0;
         const gameTimeRemaining = secondsRemaining > 0 ? `${secondsRemaining}s` : 'Time Expired';


         res.status(200).json({
            status: true,
            message: 'Game details retrieved successfully',
            gameDetails: {
               game_id: gameDetails.game_id,
               game_name: gameDetails.game_name,
               game_pic: gameDetails.game_pic,
               game_type_id: gameTypeDetails.game_type_id,
               game_type_name: gameTypeDetails.game_type_name,
               game_max_digit_allowed: gameTypeDetails.game_max_digit_allowed,
               game_min_play_amount: gameTypeDetails.game_min_play_amount,
               game_max_play_amount: gameTypeDetails.game_max_play_amount,
               prize_value: gameTypeDetails.prize_value,
               is_game_active: is_game_active,
               slot_id: activeSlot.slot_id,
               start_time: activeSlot.start_time,
               end_time: activeSlot.end_time,
               is_active: activeSlot.is_active,
               game_time_remaining: gameTimeRemaining,
            },
         });
      } else {
         res.status(200).json({
            status: true,
            message: 'Game details retrieved successfully',
            gameDetails: {
               game_id: gameDetails.game_id,
               game_name: gameDetails.game_name,
               game_pic: gameDetails.game_pic,
               game_type_id: gameTypeDetails.game_type_id,
               game_type_name: gameTypeDetails.game_type_name,
               game_max_digit_allowed: gameTypeDetails.game_max_digit_allowed,
               game_min_play_amount: gameTypeDetails.game_min_play_amount,
               game_max_play_amount: gameTypeDetails.game_max_play_amount,
               prize_value: gameTypeDetails.prize_value,
               is_game_active: is_game_active,
            },
         });
      }

   } catch (err) {
      console.error('Error:', err);
      if (err.name === 'JsonWebTokenError') {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      res.status(500).json({
         status: false,
         message: 'Internal server error',
      });
   }
});

//Game all details
router.post('/game-all-details', async (req, res) => {
   const { type } = req.body;
   const {
      version_code,
      client_type,
      device_info,
      fcm_token,
      login,
      access_token,
   } = req.headers;

   if (!type || !['USER', 'ADMIN'].includes(type)) {
      return res.status(400).json({
         status: false,
         message: 'Invalid or missing type field. Allowed values are "USER" or "ADMIN".',
      });
   }

   if (type === 'USER') {
      if (
         !version_code ||
         !client_type ||
         !device_info ||
         !fcm_token ||
         !login ||
         !access_token
      ) {
         return res.status(400).json({
            status: false,
            message: 'Missing required fields for USER login.',
         });
      }
   } else if (type === 'ADMIN') {
      if (!login || !access_token) {
         return res.status(400).json({
            status: false,
            message: 'Missing required fields for ADMIN login (login and access_token).',
         });
      }
   }

   try {
      const decoded = jwt.verify(access_token, JWT_SECRET_KEY);
      if (!decoded) {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      if (type === 'USER') {
         const tokenQuery = `
         SELECT user_id, token
         FROM users
         WHERE phone = ?;
      `;
         const [tokenResult] = await con.execute(tokenQuery, [login]);

         if (tokenResult.length === 0 || tokenResult[0].token !== access_token) {
            return res.status(401).json({
               status: false,
               message: 'Access token mismatch or user not found.',
            });
         }
      }

      if (type === 'ADMIN') {
         const adminQuery = `
         SELECT admin_id, token
         FROM app_admin_master
         WHERE phone = ?;
      `;
         const [adminResult] = await con.execute(adminQuery, [login]);

         if (adminResult.length === 0 || adminResult[0].token !== access_token) {
            return res.status(401).json({
               status: false,
               message: 'Access token mismatch or admin not found.',
            });
         }
      }

      const gameQuery = `
         SELECT Game_id AS game_id, Game_name AS game_name, Game_pic AS game_pic, is_active
         FROM game_master
         WHERE is_active = 1;
      `;
      const [gameResults] = await con.execute(gameQuery);

      if (gameResults.length === 0) {
         return res.status(404).json({
            status: false,
            message: 'No active games found.',
         });
      }

      const gameDetails = await Promise.all(
         gameResults.map(async (game) => {
            const gameTypeQuery = `
               SELECT
                  game_type_id AS game_type_id,
                  game_id AS game_id,
                  game_type_name AS game_type_name,
                  noOf_item_choose AS game_max_digit_allowed,
                  min_entry_fee AS game_min_play_amount,
                  max_entry_fee AS game_max_play_amount,
                  prize_value_noOf_times AS prize_value,
                  is_active
               FROM game_type_master
               WHERE game_id = ? AND is_active = 1;
            `;
            const [gameTypeResults] = await con.execute(gameTypeQuery, [game.game_id]);

            const gameTypesWithSlots = await Promise.all(
               gameTypeResults.map(async (gameType) => {

                  const slotQuery = `
                  SELECT
                     slot_id,
                     start_time,
                     end_time
                  FROM
                     game_slot_configuration_master
                  WHERE
                     game_id = ?
                     AND game_type_id = ?
                     AND is_active = 1;
               `;
                  const [slotResults] = await con.execute(slotQuery, [gameType.game_id, gameType.game_type_id]);

                  const is_game_active = slotResults.length > 0 ? 1 : 0;

                  return {
                     ...gameType,
                     is_game_active,
                     slotDetails: slotResults,
                  };
               })
            );

            return {
               ...game,
               game_pic: `${BASE_URL}/${game.game_pic}`,
               gameTypes: gameTypesWithSlots,
            };
         })
      );

      res.status(200).json({
         status: true,
         message: 'Game details retrieved successfully',
         gameDetails,
      });
   } catch (err) {
      console.error('Error:', err);
      if (err.name === 'JsonWebTokenError') {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      res.status(500).json({
         status: false,
         message: 'Internal server error',
      });
   }
});

//User game Submit
// router.post('/user-game-save', async (req, res) => {
//    const { user_id, game_id, game_type_id, slot_id, chosen_numbers } = req.body;
//    const {
//       version_code,
//       client_type,
//       device_info,
//       fcm_token,
//       login,
//       access_token,
//    } = req.headers;

//    if (
//       !version_code ||
//       !client_type ||
//       !device_info ||
//       !fcm_token ||
//       !login ||
//       !access_token
//    ) {
//       return res.status(400).json({
//          status: false,
//          message: 'Missing required headers',
//       });
//    }

//    if (!user_id || !game_id || !game_type_id || !slot_id || !chosen_numbers || !Array.isArray(chosen_numbers)) {
//       return res.status(400).json({
//          status: false,
//          message: 'Invalid or missing required body parameters.',
//       });
//    }

//    try {
//       const decoded = jwt.verify(access_token, JWT_SECRET_KEY);
//       if (!decoded) {
//          return res.status(401).json({
//             status: false,
//             message: 'Invalid or expired access token.',
//          });
//       }

//       const [userResult] = await con.execute(
//          `SELECT user_id, token FROM users WHERE phone = ? AND user_id = ?`,
//          [login, user_id]
//       );

//       if (userResult.length === 0 || userResult[0].token !== access_token) {
//          return res.status(401).json({
//             status: false,
//             message: 'Access token mismatch, user_id or login does not match.',
//          });
//       }

//       const totalAmount = chosen_numbers.reduce((sum, item) => sum + item.amount, 0);

//       const walletQuery = `
//          SELECT current_amount
//          FROM user_wallet_master
//          WHERE user_id = ? AND status = 1
//          ORDER BY created_at DESC
//          LIMIT 1
//       `;
//       const [walletResult] = await con.execute(walletQuery, [user_id]);

//       if (walletResult.length === 0) {
//          return res.status(400).json({
//             status: false,
//             message: 'Wallet information not found for the user.',
//          });
//       }
//       const currentWallet = walletResult[0].current_amount;

//       if (currentWallet < totalAmount) {
//          return res.status(400).json({
//             status: false,
//             message: `Insufficient wallet balance. Current balance: ${currentWallet}, Required: ${totalAmount}`,
//          });
//       }

//       const currentAmount = currentWallet - totalAmount;
//       await con.execute(
//          `UPDATE user_wallet_master SET current_amount = ? WHERE user_id = ? AND status = 1 ORDER BY created_at DESC LIMIT 1`,
//          [currentAmount, user_id]
//       );

//       const insertMapQuery = `
//          INSERT INTO user_game_map (user_id, game_id, game_type_id, slot_id, bid_Value)
//          VALUES (?, ?, ?, ?, ?)
//       `;
//       const insertValuesQuery = `
//          INSERT INTO user_game_choosen_values (user_game_map_id, chosen_value)
//          VALUES (?, ?)
//       `;

//       const insertedIds = [];
//       for (const item of chosen_numbers) {
//          const [mapResult] = await con.execute(insertMapQuery, [user_id, game_id, game_type_id, slot_id, item.amount]);
//          const userGameMapId = mapResult.insertId;

//          // Insert each chosen value into the user_game_choosen_values table
//          await con.execute(insertValuesQuery, [userGameMapId, item.number]);

//          insertedIds.push(userGameMapId);
//       }

//       // Return the success response with the updated balance and inserted IDs
//       res.status(200).json({
//          status: true,
//          message: 'Game details saved successfully',
//          currentAmount,
//          insertedIds,
//       });
//    } catch (err) {
//       console.error('Error:', err);

//       // Handle token verification error
//       if (err.name === 'JsonWebTokenError') {
//          return res.status(401).json({
//             status: false,
//             message: 'Invalid or expired access token.',
//          });
//       }

//       // Handle general errors
//       res.status(500).json({
//          status: false,
//          message: 'Internal server error',
//       });
//    }
// });

router.post('/user-game-save', async (req, res) => {
   const { user_id, game_id, game_type_id, slot_id, chosen_numbers } = req.body;
   const {
      version_code,
      client_type,
      device_info,
      fcm_token,
      login,
      access_token,
   } = req.headers;

   if (
      !version_code ||
      !client_type ||
      !device_info ||
      !fcm_token ||
      !login ||
      !access_token
   ) {
      return res.status(400).json({
         status: false,
         message: 'Missing required headers',
      });
   }

   if (!user_id || !game_id || !game_type_id || !slot_id || !chosen_numbers || !Array.isArray(chosen_numbers)) {
      return res.status(400).json({
         status: false,
         message: 'Invalid or missing required body parameters.',
      });
   }

   try {
      const decoded = jwt.verify(access_token, JWT_SECRET_KEY);
      if (!decoded) {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      const [userResult] = await con.execute(
         `SELECT user_id, token FROM users WHERE phone = ? AND user_id = ?`,
         [login, user_id]
      );

      if (userResult.length === 0 || userResult[0].token !== access_token) {
         return res.status(401).json({
            status: false,
            message: 'Access token mismatch, user_id or login does not match.',
         });
      }

      const totalAmount = chosen_numbers.reduce((sum, item) => sum + item.amount, 0);

      const walletQuery = `
         SELECT current_amount
         FROM user_wallet_master
         WHERE user_id = ? AND status = 1
         ORDER BY created_at DESC
         LIMIT 1
      `;
      const [walletResult] = await con.execute(walletQuery, [user_id]);

      if (walletResult.length === 0) {
         return res.status(400).json({
            status: false,
            message: 'Wallet information not found for the user.',
         });
      }
      const currentWallet = walletResult[0].current_amount;

      if (currentWallet < totalAmount) {
         return res.status(400).json({
            status: false,
            message: `Insufficient wallet balance. Current balance: ${currentWallet}, Required: ${totalAmount}`,
         });
      }

      const currentAmount = currentWallet - totalAmount;
      await con.execute(
         `UPDATE user_wallet_master SET current_amount = ? WHERE user_id = ? AND status = 1 ORDER BY created_at DESC LIMIT 1`,
         [currentAmount, user_id]
      );

      const particulars = 'Debit';
      const details = `Game ID: ${game_id} | Bid amount sum: ${totalAmount}`;
      const currentWalletAmount = currentAmount;

      await con.execute(
         `INSERT INTO user_wallet_transaction_history (user_id, game_id, particulars, details, current_wallet_amount)
          VALUES (?, ?, ?, ?, ?)`,
         [user_id, game_id, particulars, details, currentWalletAmount]
      );

      const insertMapQuery = `
         INSERT INTO user_game_map (user_id, game_id, game_type_id, slot_id, bid_Value)
         VALUES (?, ?, ?, ?, ?)
      `;
      const insertValuesQuery = `
         INSERT INTO user_game_choosen_values (user_game_map_id, chosen_value)
         VALUES (?, ?)
      `;

      const insertedIds = [];
      for (const item of chosen_numbers) {
         const [mapResult] = await con.execute(insertMapQuery, [user_id, game_id, game_type_id, slot_id, item.amount]);
         const userGameMapId = mapResult.insertId;

         await con.execute(insertValuesQuery, [userGameMapId, item.number]);

         insertedIds.push(userGameMapId);
      }

      res.status(200).json({
         status: true,
         message: 'Game details saved successfully',
         currentAmount,
         insertedIds,
      });
   } catch (err) {
      console.error('Error:', err);

      if (err.name === 'JsonWebTokenError') {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      res.status(500).json({
         status: false,
         message: 'Internal server error',
      });
   }
});

//Admin part
//game type name
router.post('/game-type-name', async (req, res) => {
   const login = req.headers.login;
   const accessToken = req.headers.access_token;

   if (!login || !accessToken) {
      return res.status(400).json({ status: false, message: 'Missing login or access_token headers' });
   }

   try {
      const query = 'SELECT game_type_id, game_id, game_type_name FROM game_type_master';
      const results = await con.query(query);

      res.status(200).json({
         status: true,
         message: 'Game type data fetched successfully',
         data: results[0],
      });
   } catch (err) {
      console.error('Error fetching data:', err);
      res.status(500).json({ status: false, message: 'Database query error' });
   }
});

// Game Create
router.post('/create-game', upload.single('game_pic'), async (req, res) => {
   const {
      game_name,
      game_type_name,
      min_entry_fee,
      max_entry_fee,
      noOf_item_choose,
      prize_value_noOf_times,
      start_date,
      end_date,
      is_active
   } = req.body;

   console.log(req.body, 'Received request body');

   if (!game_name || !game_type_name || !min_entry_fee || !max_entry_fee || !noOf_item_choose || !prize_value_noOf_times || !is_active) {
      return res.status(400).json({
         status: false,
         message: 'Missing required body parameters',
      });
   }

   const game_pic = req.file ? req.file.filename : '';
   if (!game_pic) {
      return res.status(400).json({
         status: false,
         message: 'Missing game image (game_pic)',
      });
   }

   const insertGameQuery = `INSERT INTO game_master
      (game_name, game_pic, is_active,start_date,end_date, app_id, created_by, updated_by)
      VALUES (?, ?, ?, ?, ?, ?,?,?)`;

   const gameValues = [game_name, game_pic, is_active, start_date, end_date, 1, 1, 1];

   try {
      const [gameResult] = await con.query(insertGameQuery, gameValues);

      const game_id = gameResult.insertId;

      const insertGameTypeQuery = `INSERT INTO game_type_master
         (game_id, game_type_name, min_entry_fee, max_entry_fee, noOf_item_choose, prize_value_noOf_times, app_id, created_by, updated_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;

      const gameTypeValues = [
         game_id,
         game_type_name,
         min_entry_fee,
         max_entry_fee,
         noOf_item_choose,
         prize_value_noOf_times,
         1,
         1,
         1
      ];

      await con.query(insertGameTypeQuery, gameTypeValues);

      res.status(200).json({ status: true, message: 'Game created successfully' });
   } catch (err) {
      console.error(err);
      res.status(500).json({ status: false, error: 'Internal Server Error' });
   }
});

//Slot Create
router.post('/create-slot', async (req, res) => {
   try {
      const { game_id, game_type_id, start_time, end_time } = req.body;

      if (!game_id || !game_type_id || !start_time || !end_time) {
         return res.status(400).json({
            status: false,
            message: 'Invalid input. Please provide all required fields.'
         });
      }

      const startTimes = Array.isArray(start_time) ? start_time : [start_time];
      const endTimes = Array.isArray(end_time) ? end_time : [end_time];

      if (startTimes.length !== endTimes.length) {
         return res.status(400).json({
            status: false,
            message: 'start_time and end_time must have matching lengths.'
         });
      }

      const app_id = 1;
      const created_by = 1;
      const modified_by = 1;
      const is_active = 1;
      const is_deleted = 0;

      const values = startTimes.map((start, index) => [
         game_id,
         game_type_id,
         app_id,
         start,
         endTimes[index],
         is_active,
         is_deleted,
         created_by,
         modified_by
      ]);

      const query = `
         INSERT INTO game_slot_configuration_master
         (game_id, game_type_id, app_id, start_time, end_time, is_active, is_deleted, created_by, modified_by)
         VALUES ?
      `;

      const [result] = await con.query(query, [values]);

      res.status(200).json({
         status: true,
         message: 'Slots created successfully!',
         insertedRows: result.affectedRows
      });

   } catch (error) {
      console.error('Error inserting slot data:', error);
      res.status(500).json({
         status: false,
         message: 'Failed to create slots. Please try again.',
         error: error.message
      });
   }
});

//slot info
router.post('/slot-info', async (req, res) => {
   const login = req.headers.login;
   const accessToken = req.headers.access_token;

   if (!login || !accessToken) {
      return res.status(400).json({ status: false, message: 'Missing login or access_token headers' });
   }

   try {
      const query = 'SELECT slot_id, game_type_id, game_id, start_time,end_time FROM game_slot_configuration_master';
      const results = await con.query(query);

      res.status(200).json({
         status: true,
         message: 'Slot data fetched successfully',
         data: results[0],
      });
   } catch (err) {
      console.error('Error fetching data:', err);
      res.status(500).json({ status: false, message: 'Database query error' });
   }
});

//Add Money
router.post('/add-money', async (req, res) => {
   const {
      version_code,
      client_type,
      device_info,
      fcm_token,
      login,
      access_token,
   } = req.headers;

   const { amount, transaction_id, notes } = req.body;

   if (
      !version_code ||
      !client_type ||
      !device_info ||
      !fcm_token ||
      !login ||
      !access_token
   ) {
      return res.status(400).json({
         status: false,
         message: 'Missing required headers',
      });
   }

   if (!amount || !transaction_id) {
      return res.status(400).json({
         status: false,
         message: 'Missing required fields in body',
      });
   }

   try {
      const decoded = jwt.verify(access_token, JWT_SECRET_KEY);
      if (!decoded) {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token',
         });
      }

      const userQuery = `
         SELECT user_id, token
         FROM users
         WHERE phone = ? AND token = ?;
      `;
      const [userResult] = await con.execute(userQuery, [login, access_token]);

      if (userResult.length === 0) {
         return res.status(401).json({
            status: false,
            message: 'Invalid login or access token',
         });
      }

      const user_id = userResult[0].user_id;

      const walletQuery = `
         INSERT INTO user_wallet_master (user_id, app_id, wallet_amount, transaction_id,notes, created_at, updated_at)
         VALUES (?, ?, ?, ?,?, NOW(), NOW());
      `;
      await con.execute(walletQuery, [user_id, 1, amount, transaction_id, notes]);

      res.status(200).json({
         status: true,
         message: 'Money request sent successfully !',
      });
   } catch (err) {
      console.error('Error:', err);
      if (err.name === 'JsonWebTokenError') {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token',
         });
      }

      res.status(500).json({
         status: false,
         message: 'Internal server error',
      });
   }
});

//user wallet info
router.post('/user-wallet-info', async (req, res) => {
   const { login, access_token } = req.headers;

   try {
      const adminQuery = `
         SELECT admin_id, token
         FROM app_admin_master
         WHERE phone = ?;
      `;
      const [adminResult] = await con.execute(adminQuery, [login]);

      if (adminResult.length === 0 || adminResult[0].token !== access_token) {
         return res.status(401).json({
            status: false,
            message: 'Access token mismatch or admin not found.',
            data: []
         });
      }

      const query = `
         SELECT
            uwm.user_id,
            uwm.wallet_id,
            uwm.wallet_amount,
            uwm.transaction_id,
            CASE
               WHEN uwm.status = 0 THEN 'Pending'
               WHEN uwm.status = 1 THEN 'Approved'
               WHEN uwm.status = 2 THEN 'Rejected'
               ELSE 'Unknown'
            END AS status,
            uwm.created_at,
            u.name,
            u.email,
            u.phone
         FROM
            user_wallet_master uwm
         INNER JOIN
            users u
         ON
            uwm.user_id = u.user_id;
      `;

      const [results] = await con.execute(query);

      const formattedResults = results.map((row) => ({
         ...row,
         created_at: moment(row.created_at).format('YYYY-MM-DD HH:mm:ss'),
      }));

      if (formattedResults.length === 0) {
         return res.status(200).json({
            status: true,
            data: [],
            message: 'No user or wallet data found.'
         });
      }

      res.status(200).json({
         status: true,
         data: formattedResults,
         message: 'User wallet data retrieved successfully.'
      });
   } catch (err) {
      console.error('Error fetching user wallet info:', err);
      res.status(500).json({
         status: false,
         data: [],
         message: 'Internal server error.'
      });
   }
});

//wallet balance status update
// router.put('/wallet-status-update/:wallet_id', async (req, res) => {
//    const walletId = req.params.wallet_id;
//    const { status } = req.body;

//    if (status === undefined) {
//       return res.status(400).json({ status: false, error: 'Status is required' });
//    }

//    try {
//       const updateStatusQuery = `UPDATE user_wallet_master SET status = ? WHERE wallet_id = ?`;
//       const [statusResult] = await con.query(updateStatusQuery, [status, walletId]);

//       if (statusResult.affectedRows > 0) {
//          if (status === 1) {
//             const updateAmountQuery = `
//                UPDATE user_wallet_master
//                SET current_amount = wallet_amount
//                WHERE wallet_id = ?`;
//             await con.query(updateAmountQuery, [walletId]);
//          }
//          res.status(200).json({ status: true, message: 'Wallet status updated successfully.' });
//       } else {
//          res.status(404).json({ status: false, message: 'Wallet data not found.' });
//       }
//    } catch (err) {
//       console.error('Error updating wallet status:', err);
//       res.status(500).json({ status: false, error: 'Database update failed.' });
//    }
// });


router.put('/wallet-status-update/:wallet_id', async (req, res) => {
   const walletId = req.params.wallet_id;
   const { status } = req.body;

   if (status === undefined) {
      return res.status(400).json({ status: false, error: 'Status is required' });
   }

   try {
      const updateStatusQuery = `UPDATE user_wallet_master SET status = ? WHERE wallet_id = ?`;
      const [statusResult] = await con.query(updateStatusQuery, [status, walletId]);

      if (statusResult.affectedRows > 0) {
         if (status === 1) {
            const getUserQuery = `SELECT user_id FROM user_wallet_master WHERE wallet_id = ?`;
            const [userResult] = await con.query(getUserQuery, [walletId]);

            if (userResult.length > 0) {
               const userId = userResult[0].user_id;

               const sumAmountQuery = `
                  SELECT SUM(wallet_amount) AS totalAmount
                  FROM user_wallet_master
                  WHERE user_id = ? AND status = 1
               `;
               const [sumResult] = await con.query(sumAmountQuery, [userId]);

               if (sumResult.length > 0) {
                  const totalAmount = sumResult[0].totalAmount;

                  const updateAmountQuery = `
                     UPDATE user_wallet_master
                     SET current_amount = ?
                     WHERE wallet_id = ?
                  `;
                  await con.query(updateAmountQuery, [totalAmount, walletId]);
               }
            }
         }
         res.status(200).json({ status: true, message: 'Wallet status updated successfully.' });
      } else {
         res.status(404).json({ status: false, message: 'Wallet data not found.' });
      }
   } catch (err) {
      console.error('Error updating wallet status:', err);
      res.status(500).json({ status: false, error: 'Database update failed.' });
   }
});


//Wallet Details
// router.post('/wallet-details', async (req, res) => {
//    try {
//       const {
//          version_code,
//          client_type,
//          device_info,
//          fcm_token,
//          login,
//          access_token,
//       } = req.headers;

//       if (!version_code || !client_type || !device_info || !fcm_token || !login || !access_token) {
//          return res.status(400).json({
//             status: false,
//             message: "Missing required headers."
//          });
//       }

//       const { user_id } = req.body;
//       if (!user_id) {
//          return res.status(400).json({
//             status: false,
//             message: "Missing user_id in the request body."
//          });
//       }

//       const userQuery = `
//          SELECT user_id
//          FROM users
//          WHERE phone = ? AND token = ? AND user_id = ?
//       `;
//       const [userResults] = await con.execute(userQuery, [login, access_token, user_id]);

//       if (userResults.length === 0) {
//          return res.status(403).json({
//             status: false,
//             message: "Authentication failed or mismatched user details."
//          });
//       }

//       const walletQuery = `
//          SELECT current_amount, status,notes, created_at, notes
//          FROM user_wallet_master
//          WHERE user_id = ?
//       `;
//       const [walletResults] = await con.execute(walletQuery, [user_id]);

//       if (walletResults.length === 0) {
//          return res.status(200).json({
//             status: true,
//             message: "No wallet details found for the given user ID.",
//             data: { current_amount: 0 }
//          });
//       }

//       walletResults.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

//       const latestRecord = walletResults[0];

//       let totalWalletAmount = 0;
//       const activeRows = walletResults.filter(row => row.status === 1);

//       if (activeRows.length > 0) {
//          totalWalletAmount = activeRows.reduce((sum, row) => sum + parseFloat(row.current_amount), 0);
//       } else {
//          totalWalletAmount = 0;
//       }

//       const formattedCreatedAt = moment(latestRecord.created_at)
//          .tz(timezone)
//          .format('YYYY-MM-DD HH:mm:ss');

//       res.status(200).json({
//          status: true,
//          message: "Wallet details fetched successfully.",
//          data: {
//             current_amount: totalWalletAmount,
//             notes: latestRecord.notes || null,
//             min_recharge_amount: 10,
//             min_deposit_amount: 200,
//             min_withdrawal_amount: 500,
//             max_recharge_amount: 1000,
//             created_at: formattedCreatedAt
//          },
//       });
//    } catch (err) {
//       console.error('Error:', err);
//       res.status(500).json({
//          status: false,
//          message: "An error occurred while fetching wallet details."
//       });
//    }
// });

router.post('/wallet-details', async (req, res) => {
   try {
      const {
         version_code,
         client_type,
         device_info,
         fcm_token,
         login,
         access_token,
      } = req.headers;

      if (!version_code || !client_type || !device_info || !fcm_token || !login || !access_token) {
         return res.status(400).json({
            status: false,
            message: "Missing required headers."
         });
      }

      const { user_id } = req.body;
      if (!user_id) {
         return res.status(400).json({
            status: false,
            message: "Missing user_id in the request body."
         });
      }

      const userQuery = `
         SELECT user_id
         FROM users
         WHERE phone = ? AND token = ? AND user_id = ?
      `;
      const [userResults] = await con.execute(userQuery, [login, access_token, user_id]);

      if (userResults.length === 0) {
         return res.status(403).json({
            status: false,
            message: "Authentication failed or mismatched user details."
         });
      }

      const walletQuery = `
         SELECT current_amount, notes, created_at
         FROM user_wallet_master
         WHERE user_id = ? AND status = 1
         ORDER BY created_at DESC
         LIMIT 1
      `;
      const [walletResults] = await con.execute(walletQuery, [user_id]);

      if (walletResults.length === 0) {
         return res.status(200).json({
            status: true,
            message: "No wallet details found for the given user ID with active status.",
            data: {
               current_amount: 0,
               notes: null,
               min_recharge_amount: 10,
               min_deposit_amount: 200,
               min_withdrawal_amount: 500,
               max_recharge_amount: 1000,
               created_at: null
            }
         });
      }

      const latestRecord = walletResults[0];
      const formattedCreatedAt = moment(latestRecord.created_at)
         .tz(timezone)
         .format('YYYY-MM-DD HH:mm:ss');

      res.status(200).json({
         status: true,
         message: "Wallet details fetched successfully.",
         data: {
            current_amount: parseFloat(latestRecord.current_amount),
            notes: latestRecord.notes || null,
            min_recharge_amount: 10,
            min_deposit_amount: 200,
            min_withdrawal_amount: 500,
            max_recharge_amount: 1000,
            created_at: formattedCreatedAt
         }
      });
   } catch (err) {
      console.error('Error:', err);
      res.status(500).json({
         status: false,
         message: "An error occurred while fetching wallet details."
      });
   }
});

// user transactions info
router.post('/transaction', async (req, res) => {
   const { user_id } = req.body;

   const {
      version_code,
      client_type,
      device_info,
      fcm_token,
      login,
      access_token,
   } = req.headers;

   if (
      !version_code ||
      !client_type ||
      !device_info ||
      !fcm_token ||
      !login ||
      !access_token
   ) {
      return res.status(400).json({
         status: false,
         message: 'Missing required headers',
      });
   }

   if (!user_id) {
      return res.status(400).json({
         status: false,
         message: 'User ID is required.',
      });
   }

   try {
      const decoded = jwt.verify(access_token, JWT_SECRET_KEY);
      if (!decoded) {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      const [userResult] = await con.execute(
         `SELECT user_id, token FROM users WHERE phone = ? AND user_id = ?`,
         [login, user_id]
      );

      if (userResult.length === 0 || userResult[0].token !== access_token) {
         return res.status(401).json({
            status: false,
            message: 'Access token mismatch, user_id or login does not match.',
         });
      }
      const transactionQuery = `
           SELECT user_wallet_transaction_id, game_id, particulars, details, current_wallet_amount
           FROM user_wallet_transaction_history
           WHERE user_id = ?
           ORDER BY created_at DESC
       `;

      const [transactionHistory] = await con.execute(transactionQuery, [user_id]);

      return res.status(200).json({
         status: true,
         message: transactionHistory.length === 0
            ? 'No transaction history found for this user.'
            : 'Transaction history fetched successfully.',
         data: transactionHistory.length === 0 ? [] : transactionHistory,
      });

   } catch (err) {
      console.error('Error:', err);

      if (err.name === 'JsonWebTokenError') {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      return res.status(500).json({
         status: false,
         message: 'Internal server error',
      });
   }
});

//Withdrawal Request
router.post('/withdrawal-request', async (req, res) => {
   const {
      version_code,
      client_type,
      device_info,
      fcm_token,
      login,
      access_token
   } = req.headers;

   const { amount, transaction_id, notes } = req.body;

   if (!version_code || !client_type || !device_info || !fcm_token || !login || !access_token) {
      return res.status(400).json({
         status: false,
         message: 'Missing required headers',
      });
   }
   if (!amount || !transaction_id) {
      return res.status(400).json({
         status: false,
         message: 'Missing required fields in body',
      });
   }

   if (amount < 500) {
      return res.status(400).json({
         status: false,
         message: 'Minimum withdrawal amount is 500',
      });
   }

   try {
      const decoded = jwt.verify(access_token, JWT_SECRET_KEY);
      if (!decoded) {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token',
         });
      }

      const userQuery = `
         SELECT user_id, token
         FROM users
         WHERE phone = ? AND token = ?;
      `;
      const [userResult] = await con.execute(userQuery, [login, access_token]);

      if (userResult.length === 0) {
         return res.status(401).json({
            status: false,
            message: 'Invalid login or access token',
         });
      }

      const user_id = userResult[0].user_id;

      const bankInfoQuery = `
         SELECT *
         FROM user_bank_info
         WHERE user_id = ?;
      `;
      const [bankInfoResult] = await con.execute(bankInfoQuery, [user_id]);

      if (bankInfoResult.length === 0) {
         return res.status(400).json({
            status: false,
            message: 'Update your bank information',
         });
      }

      const walletQuery = `
              SELECT current_amount
                   FROM user_wallet_master
                   WHERE user_id = ? AND status = 1
                       ORDER BY created_at DESC
                           LIMIT 1;
                             `;
      const [walletResult] = await con.execute(walletQuery, [user_id]);

      if (walletResult.length === 0) {
         return res.status(400).json({
            status: false,
            message: 'Wallet balance not found',
         });
      }

      const currentBalance = parseFloat(walletResult[0].current_amount);

      if (isNaN(currentBalance) || currentBalance < parseFloat(amount)) {
         return res.status(400).json({
            status: false,
            message: 'Insufficient wallet balance',
         });
      }

      const insertQuery = `
         INSERT INTO user_withdrawal_master (
            user_id,
            app_id,
            withdrawal_amount,
            transaction_id,
            notes,
            status
         ) VALUES (?, ?, ?, ?,?, ?);
      `;

      const [insertResult] = await con.execute(insertQuery, [
         user_id,
         1,
         amount,
         transaction_id,
         notes,
         0
      ]);

      return res.status(200).json({
         status: true,
         message: 'Withdrawal request submitted successfully',
         data: {
            withdrawal_id: insertResult.insertId,
            user_id,
            amount,
            transaction_id,
            status: 0
         }
      });
   } catch (error) {
      console.error(error);
      return res.status(500).json({
         status: false,
         message: 'Internal server error',
      });
   }
});

//Bank info
router.post('/add-bank-info', async (req, res) => {
   const headers = req.headers;
   const {
      version_code, client_type, device_info, fcm_token, login, access_token
   } = headers;

   const {
      bank_id,
      user_id,
      account_holder_name,
      account_number,
      ifsc_code,
      paytm_number,
      upi_address
   } = req.body;

   // Validate headers and body fields
   if (!user_id || !access_token || !login || !version_code || !client_type || !device_info || !fcm_token) {
      return res.status(400).json({ status: false, message: 'Missing required fields in headers or body.' });
   }

   try {
      // Verify JWT token
      const decoded = jwt.verify(access_token, JWT_SECRET_KEY);
      if (!decoded) {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      // Check if the user exists and matches the provided access token
      const [userResult] = await con.execute(
         `SELECT user_id, token FROM users WHERE phone = ? AND user_id = ?`,
         [login, user_id]
      );

      if (userResult.length === 0 || userResult[0].token !== access_token) {
         return res.status(401).json({
            status: false,
            message: 'Access token mismatch, user_id or login does not match.',
         });
      }

      if (bank_id) {
         // Update operation
         const updateQuery = `
            UPDATE user_bank_info
            SET
               account_holder_name = ?,
               account_number = ?,
               ifsc_code = ?,
               paytm_number = ?,
               upi_address = ?,
               updated_at = NOW()
            WHERE bank_id = ? AND user_id = ?
         `;
         const [updateResult] = await con.execute(updateQuery, [
            account_holder_name,
            account_number,
            ifsc_code,
            paytm_number,
            upi_address,
            bank_id,
            user_id
         ]);

         if (updateResult.affectedRows === 0) {
            return res.status(404).json({
               status: false,
               message: 'Bank info not found or user_id mismatch.',
            });
         }

         return res.status(200).json({
            status: true,
            message: 'Bank info updated successfully',
            data: {
               bank_id,
               user_id,
               account_holder_name,
               account_number,
               ifsc_code,
               paytm_number,
               upi_address
            }
         });
      } else {
         // Add operation
         const addQuery = `
            INSERT INTO user_bank_info (
               user_id,
               app_id,
               account_holder_name,
               account_number,
               ifsc_code,
               paytm_number,
               upi_address,
               created_at
            ) VALUES (?, 1, ?, ?, ?, ?, ?, NOW())
         `;
         const [addResult] = await con.execute(addQuery, [
            user_id,
            account_holder_name,
            account_number,
            ifsc_code,
            paytm_number,
            upi_address
         ]);

         return res.status(200).json({
            status: true,
            message: 'Bank info added successfully',
            data: {
               bank_id: addResult.insertId,
               user_id,
               account_holder_name,
               account_number,
               ifsc_code,
               paytm_number,
               upi_address
            }
         });
      }
   } catch (error) {
      console.error(error);
      return res.status(500).json({ status: false, message: 'Internal server error' });
   }
});


//user withdrawal info
router.post('/user-withdrawal-info', async (req, res) => {
   const { login, access_token } = req.headers;

   try {
      const adminQuery = `
         SELECT admin_id, token
         FROM app_admin_master
         WHERE phone = ?;
      `;
      const [adminResult] = await con.execute(adminQuery, [login]);

      if (adminResult.length === 0 || adminResult[0].token !== access_token) {
         return res.status(401).json({
            status: false,
            message: 'Access token mismatch or admin not found.',
            data: []
         });
      }

      const query = `
      SELECT
         u.user_id,
         u.name,
         u.email,
         u.phone,
         uwm.withdrawal_id,
         uwm.account_holder_name,
         uwm.account_number,
         uwm.ifsc_code,
         uwm.paytm_number,
         uwm.upi_address,
         uwm.withdrawal_amount,
         CASE
            WHEN uwm.status = 0 THEN 'Pending'
            WHEN uwm.status = 1 THEN 'Approved'
            WHEN uwm.status = 2 THEN 'Rejected'
            ELSE 'Unknown'
         END AS statusText,
         uwm.created_at
      FROM
         users u
      INNER JOIN
         user_withdrawal_master uwm
      ON
         u.user_id = uwm.user_id;
   `;


      const [results] = await con.execute(query);

      const formattedResults = results.map((row) => ({
         ...row,
         created_at: moment(row.created_at).format('YYYY-MM-DD HH:mm:ss'),
      }));

      if (formattedResults.length === 0) {
         return res.status(200).json({
            status: true,
            data: [],
            message: 'No user or wallet data found.'
         });
      }

      res.status(200).json({
         status: true,
         message: 'User wallet data retrieved successfully.',
         data: formattedResults,
      });
   } catch (err) {
      console.error('Error fetching user wallet info:', err);
      res.status(500).json({
         status: false,
         data: [],
         message: 'Internal server error.'
      });
   }
});

//Result
//slot list api
router.post('/slot-list', async (req, res) => {
   const { login, access_token } = req.headers;
   const { game_id, game_type_id } = req.body;
   try {
      const adminQuery = `
         SELECT admin_id, token
         FROM app_admin_master
         WHERE phone = ?;
      `;
      const [adminResult] = await con.execute(adminQuery, [login]);

      if (adminResult.length === 0 || adminResult[0].token !== access_token) {
         return res.status(401).json({
            status: false,
            message: 'Access token mismatch or admin not found.',
            data: []
         });
      }

      if (!game_id || !game_type_id) {
         return res.status(400).json({
            status: false,
            message: 'game_id and game_type_id are required.',
         });
      }

      const query = `
           SELECT slot_id, start_time, end_time
           FROM game_slot_configuration_master
           WHERE game_id = ?
             AND game_type_id = ?
             AND is_active = 1
       `;

      const [rows] = await con.execute(query, [game_id, game_type_id]);

      if (rows.length === 0) {
         return res.status(200).json({
            status: true,
            message: 'No data available for the given game_id and game_type_id.',
            data: [],
         });
      }

      res.status(200).json({
         status: true,
         message: 'Data fetched successfully.',
         data: rows,
      });
   } catch (error) {
      console.error('Error fetching game data:', error.message);
      res.status(500).json({
         status: false,
         message: 'Internal server error.',
         error: error.message,
      });
   }
});

//Result Create
router.post('/result-create', async (req, res) => {
   try {
      const { login, access_token } = req.headers;
      const { game_id, game_type_id, slot_id, winner_values, result_date } = req.body;

      const adminQuery = `
      SELECT admin_id, token
      FROM app_admin_master
      WHERE phone = ?;
   `;
      const [adminResult] = await con.execute(adminQuery, [login]);

      if (adminResult.length === 0 || adminResult[0].token !== access_token) {
         return res.status(401).json({
            status: false,
            message: 'Access token mismatch or admin not found.',
            data: []
         });
      }

      if (!game_id || !game_type_id || !slot_id || !slot_id.length || !winner_values || !result_date) {
         return res.status(400).json({ status: false, message: 'Invalid input data' });
      }

      for (const slot of slot_id) {
         const winnerValue = winner_values[slot];
         if (!winnerValue) {
            return res.status(400).json({ status: false, message: `Winner value is missing for slot ${slot}` });
         }

         await con.query(
            `INSERT INTO result_master (game_id, game_type_id, slot_id,result_date, winner_value) VALUES (?, ?, ?,?, ?)`,
            [game_id, game_type_id, slot, result_date, winnerValue]
         );
      }

      res.status(200).json({ status: true, message: 'Result created successfully' });
   } catch (error) {
      console.error('Error creating result:', error);
      res.status(500).json({ status: false, message: 'Internal server error' });
   }
});

//Result list
router.post('/result-list', async (req, res) => {
   try {
      const { login, access_token } = req.headers;

      const adminQuery = `
      SELECT admin_id, token
      FROM app_admin_master
      WHERE phone = ?;
   `;
      const [adminResult] = await con.execute(adminQuery, [login]);

      if (adminResult.length === 0 || adminResult[0].token !== access_token) {
         return res.status(401).json({
            status: false,
            message: 'Access token mismatch or admin not found.',
            data: []
         });
      }

      const [rows] = await con.execute('SELECT result_id, game_id, game_type_id, slot_id,result_date, winner_value FROM result_master');

      const formattedRows = rows.map(row => {
         return {
            ...row,
            result_date: moment.tz(row.result_date, timezone).format('YYYY-MM-DD'),
            created_at: moment.tz(row.created_at, timezone).format('YYYY-MM-DD HH:mm:ss'),
         };
      });

      res.status(200).json({
         status: true,
         message: 'Data fetched successfully',
         data: formattedRows,
      });
   } catch (err) {
      console.error('Error fetching data:', err);
      res.status(500).json({
         status: false,
         message: 'Error fetching data',
      });
   }
});

//Result update
router.put('/update-result', async (req, res) => {
   const { login, access_token } = req.headers;
   const { result_id, winner_value } = req.body;

   if (!login || !access_token || !result_id || !winner_value) {
      return res.status(400).json({
         status: false,
         message: "Missing required headers or body parameters.",
      });
   }

   try {
      const decoded = jwt.verify(access_token, JWT_SECRET_KEY);
      if (!decoded) {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      const adminQuery = `
      SELECT admin_id, token
      FROM app_admin_master
      WHERE phone = ?;
   `;
      const [adminResult] = await con.execute(adminQuery, [login]);

      if (adminResult.length === 0 || adminResult[0].token !== access_token) {
         return res.status(401).json({
            status: false,
            message: 'Access token mismatch or admin not found.',
            data: []
         });
      }

      const updateQuery = `
         UPDATE result_master
         SET winner_value = ?
         WHERE result_id = ?;
      `;

      const [updateResult] = await con.query(updateQuery, [winner_value, result_id]);

      if (updateResult.affectedRows === 0) {
         return res.status(404).json({
            status: false,
            message: 'Result not found or update failed.',
         });
      }

      return res.status(200).json({
         status: true,
         message: 'Result updated successfully.',
      });

   } catch (error) {
      if (error.name === 'JsonWebTokenError') {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token.',
         });
      }

      console.error(error);
      return res.status(500).json({
         status: false,
         message: 'Internal server error.',
      });
   }
});

//User bid details
router.post('/user-bid-details', async (req, res) => {
   const {
      version_code,
      client_type,
      device_info,
      fcm_token,
      login,
      access_token
   } = req.headers;

   const { user_id } = req.body;

   if (!version_code || !client_type || !device_info || !fcm_token || !login || !access_token) {
      return res.status(400).json({
         status: false,
         message: 'Missing required headers',
      });
   }
   if (!user_id) {
      return res.status(400).json({
         status: false,
         message: 'Missing user_id in the request body',
      });
   }

   try {
      const decoded = jwt.verify(access_token, JWT_SECRET_KEY);
      if (!decoded) {
         return res.status(401).json({
            status: false,
            message: 'Invalid or expired access token',
         });
      }

      const userQuery = `
           SELECT user_id, token
           FROM users
           WHERE phone = ? AND token = ?;
       `;
      const [userResult] = await con.execute(userQuery, [login, access_token]);

      if (userResult.length === 0) {
         return res.status(401).json({
            status: false,
            message: 'Invalid login or access token',
         });
      }

      const last30Days = moment().subtract(30, 'days').format('YYYY-MM-DD HH:mm:ss');

      const gameMapQuery = `
           SELECT
               ugm.user_game_map_id,
               ugm.slot_id,
               ugm.game_id,
               ugm.game_type_id,
               ugm.bid_value,
               ugcv.chosen_value,
               ugcv.created_at
           FROM user_game_map AS ugm
           LEFT JOIN user_game_choosen_values AS ugcv
               ON ugm.user_game_map_id = ugcv.user_game_map_id
           WHERE ugm.user_id = ? AND ugcv.created_at >= ?;
       `;
      const [gameMapData] = await con.execute(gameMapQuery, [user_id, last30Days]);

      if (gameMapData.length === 0) {
         return res.status(200).json({
            status: true,
            message: 'No bid details found',
            data: []
         });
      }

      const groupedData = {};

      for (const gameMap of gameMapData) {
         const { game_id, game_type_id, slot_id, bid_value, chosen_value, created_at } = gameMap;

         const formattedCreatedAt = moment(created_at)
            .tz('timezone')
            .format('YYYY-MM-DD HH:mm:ss');

         const gameQuery = `
               SELECT game_name
               FROM game_master
               WHERE game_id = ?;
           `;
         const [gameData] = await con.execute(gameQuery, [game_id]);

         const gameTypeQuery = `
               SELECT game_type_name
               FROM game_type_master
               WHERE game_type_id = ?;
           `;
         const [gameTypeData] = await con.execute(gameTypeQuery, [game_type_id]);

         const slotQuery = `
               SELECT start_time, end_time
               FROM game_slot_configuration_master
               WHERE slot_id = ?;
           `;
         const [slotData] = await con.execute(slotQuery, [slot_id]);

         if (!groupedData[formattedCreatedAt]) {
            groupedData[formattedCreatedAt] = {
               game_name: gameData[0]?.game_name || null,
               game_type_name: gameTypeData[0]?.game_type_name || null,
               start_time: slotData[0]?.start_time || null,
               end_time: slotData[0]?.end_time || null,
               created_at: formattedCreatedAt,
               bids: [],
            };
         }

         groupedData[formattedCreatedAt].bids.push({
            bid_value,
            chosen_value
         });
      }

      const responseData = Object.values(groupedData);

      return res.status(200).json({
         status: true,
         message: 'User bid details retrieved successfully',
         data: responseData
      });
   } catch (error) {
      console.error(error);
      return res.status(500).json({
         status: false,
         message: 'Internal server error',
      });
   }
});

router.get('/logout', (req, res) => {
   res.clearCookie('token');
   return res.json({ Status: true });
});

export { router as apiRoutes };
