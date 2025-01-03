import express from "express";
import cors from 'cors';
import { apiRoutes } from "./Routes/apiRoutes.js";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from 'url';

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;

app.use(cors({
   origin: "http://localhost:5173",
   methods: ['GET', 'POST', 'PUT', "DELETE"],
   credentials: true
}));
app.options('*', cors());
app.use(express.json());
app.use(cookieParser());
app.use('/api', apiRoutes);
app.use(express.static('Public'));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.listen(PORT, () => {
   console.log(`Server is running on port ${PORT}`);
});
