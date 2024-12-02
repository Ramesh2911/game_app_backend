import express from "express";
import con from "../config/db.js";
import jwt from "jsonwebtoken";
import bcrypt from 'bcryptjs';
import moment from "moment-timezone";

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
   const { version_code, client_type, device_info, fcm_token, login, access_token } = req.headers;

   if (!version_code || !client_type || !device_info || !fcm_token) {
      return res.status(400).json({
         status: false,
         message: 'Missing required headers: version_code, client_type, device_info, or fcm_token',
      });
   }

   const isUserLoggedIn = login && access_token;
   if (login && !access_token) {
      return res.status(401).json({
         status: false,
         message: 'Missing access_token for logged-in user',
      });
   }

   try {
      const versionQuery = `
         SELECT version_code, version_name, update_note, update_date, app_url, is_mandatory
         FROM app_version
         WHERE client_type = ? AND is_active = 1
         ORDER BY id DESC
         LIMIT 1
      `;
      const [versionResult] = await con.query(versionQuery, [client_type]);

      const timezone = 'Asia/Kolkata';
      const formattedUpdateDate = moment(versionResult[0].update_date)
         .tz(timezone)
         .format('YYYY-MM-DD HH:mm:ss');

      if (!versionResult || versionResult.length === 0) {
         return res.status(404).json({
            status: false,
            message: 'No active version found for the specified client type',
         });
      }

      const configQuery = `
         SELECT id, config_key, value, client_type, is_active
         FROM app_configuration
         WHERE client_type = ? AND is_active = 1
      `;
      const [configResult] = await con.query(configQuery, [client_type]);

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
         message: 'Missing user_id in request body',
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

      if (tokenResult[0].user_id !== parseInt(user_id, 10)) {
         return res.status(403).json({
            status: false,
            message: 'User ID does not match the authenticated user.',
         });
      }

      const query = `
       SELECT Game_id, Game_name, Game_pic, is_active
       FROM game_master
       WHERE is_active = 1
     `;
      const [results] = await con.execute(query);

      res.status(200).json({
         status: true,
         message: 'Game list retrieved successfully',
         gameList: results,
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
   const { game_id } = req.body;
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

   if (!game_id) {
      return res.status(400).json({
         status: false,
         message: 'Missing game_id in request body',
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
       SELECT
         Slot_id AS slot_id,
         game_type_id AS game_type_id,
         game_type_id AS game_type_id,
         app_id AS app_id,
         Start_date_time AS start_date_time,
         End_date_time AS end_date_time,
         is_active
       FROM game_slot_configuration_master
       WHERE game_id = ? AND game_type_id = ? AND is_active = 1;
     `;
      const [slotResults] = await con.execute(slotQuery, [game_id, game_type_id]);

      const slotDetails = slotResults.length > 0 ? slotResults : [];

      res.status(200).json({
         status: true,
         message: 'Game details retrieved successfully',
         gameDetails: {
            ...gameDetails,
            gameType: {
               game_type_id: gameTypeDetails.game_type_id,
               game_type_name: gameTypeDetails.game_type_name,
               game_max_digit_allowed: gameTypeDetails.game_max_digit_allowed,
               game_min_play_amount: gameTypeDetails.game_min_play_amount,
               game_max_play_amount: gameTypeDetails.game_max_play_amount,
               prize_value: gameTypeDetails.prize_value,
            },
            slotDetails,
         },
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






router.get('/logout', (req, res) => {
   res.clearCookie('token');
   return res.json({ Status: true });
});

export { router as apiRoutes };