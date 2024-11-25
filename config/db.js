import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
dotenv.config();

let con;

try {
   con = mysql.createPool({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
   });

   console.log("Database connection pool created successfully");
} catch (error) {
   console.error("Error creating database connection pool:", error);
}

export default con;
