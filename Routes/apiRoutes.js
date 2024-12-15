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
         user_id AS id,
         name,
         email,
         phone
      FROM
         users
      WHERE
         phone = ?;
   `;

      const [results] = await con.query(userInfoQuery, [login]);

      if (results.length === 0) {
         return res.status(404).json({
            status: false,
            message: 'User not found.',
         });
      }

      const user = results[0];

      return res.status(200).json({
         status: true,
         message: 'User details fetched successfully.',
         data: {
            id: user.id,
            name: user.name,
            email: user.email,
            phone: user.phone,
         },
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

//Wallet Details
router.post('/wallet-details', async (req, res) => {
   try {
      // Validate headers
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

      // Validate body
      const { user_id } = req.body;
      if (!user_id) {
         return res.status(400).json({
            status: false,
            message: "Missing user_id in the request body."
         });
      }

      // Fetch wallet details from database
      const query = `SELECT wallet_amount AS wallet_amount, 10 AS min_recharge_amount, 1000 AS max_recharge_amount, 500 AS min_withdrawal_amount FROM user_wallet_master WHERE user_id = ?`;
      const [results] = await con.execute(query, [user_id]);

      if (results.length === 0) {
         return res.status(404).json({
            status: false,
            message: "User wallet details not found."
         });
      }

      // Respond with wallet details
      res.status(200).json({
         status: true,
         message: "Wallet details fetched successfully.",
         data: results[0],
      });
   } catch (err) {
      console.error('Error:', err);
      res.status(500).json({
         status: false,
         message: "An error occurred while fetching wallet details."
      });
   }
});

//Wallet transactions
router.post('/wallet-transactions', async (req, res) => {
   try {
      // Validate headers
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

      // Validate body
      const { wallet_id } = req.body;
      if (!wallet_id) {
         return res.status(400).json({
            status: false,
            message: "Missing user_id or wallet_id in the request body."
         });
      }

      // Fetch wallet transactions for the last 30 days
      const query = `
       SELECT user_wallet_transaction_id AS transactionId, wallet_id AS walletId, game_id AS gameId, particulars, details, current_wallet_amount AS currentWalletAmount, created_at AS createdAt
       FROM user_wallet_transaction_history
       WHERE wallet_id = ? AND created_at >= NOW() - INTERVAL 30 DAY
       ORDER BY created_at DESC`;

      const [results] = await con.execute(query, [wallet_id]);



      if (results.length === 0) {
         return res.status(404).json({
            status: false,
            message: "No wallet transactions found for the last 30 days."
         });
      }

      // Respond with wallet transactions
      res.status(200).json({
         status: true,
         message: "Wallet transactions fetched successfully.",
         data: results,
      });
   } catch (err) {
      console.error('Error:', err);
      res.status(500).json({
         status: false,
         message: "An error occurred while fetching wallet transactions."
      });
   }
});


router.get('/logout', (req, res) => {
   res.clearCookie('token');
   return res.json({ Status: true });
});

export { router as apiRoutes };
