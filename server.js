const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Hardcoded Admin Credentials (Change these for production!)
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'SecureAdminPassword123!';

// Ensure necessary directories exist
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

// Initialize SQLite Database
const db = new sqlite3.Database(path.join(DATA_DIR, 'metadata.db'), (err) => {
    if (err) console.error('Database connection error:', err.message);
    else console.log('Connected to the SQLite database.');
});

// Create tables if they don't exist
db.run(`CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    originalname TEXT NOT NULL,
    filepath TEXT NOT NULL,
    password_hash TEXT,
    expiry_type TEXT NOT NULL,
    expiry_time INTEGER,
    download_count INTEGER DEFAULT 0
)`);

// Express Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Configure Multer Storage
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOADS_DIR);
    },
    filename: (req, file, cb) => {
        const uniquePrefix = Date.now() + '-' + crypto.randomBytes(4).toString('hex');
        cb(null, uniquePrefix + '-' + file.originalname);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB Limit
});

// Periodic Background Cleaner for Expired Files (Runs every 1 minute)
setInterval(() => {
    const now = Date.now();
    db.all(`SELECT * FROM files WHERE expiry_time IS NOT NULL AND expiry_time <= ?`, [now], (err, rows) => {
        if (err) return console.error('Cleanup error:', err.message);
        rows.forEach(file => {
            if (fs.existsSync(file.filepath)) {
                fs.unlinkSync(file.filepath);
            }
            db.run(`DELETE FROM files WHERE id = ?`, [file.id]);
            console.log(`Auto-deleted expired file: ${file.originalname}`);
        });
    });
}, 60000);

// --- API ENDPOINTS ---

// 1. File Upload Route
app.post('/api/upload', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded.' });
        }

        const { password, expiry } = req.body;
        const fileId = crypto.randomBytes(8).toString('hex'); // Shareable unique ID
        
        let passwordHash = null;
        if (password && password.trim() !== "") {
            passwordHash = await bcrypt.hash(password, 10);
        }

        let expiryTime = null;
        const now = Date.now();
        if (expiry === '1h') expiryTime = now + (60 * 60 * 1000);
        else if (expiry === '24h') expiryTime = now + (24 * 60 * 60 * 1000);
        
        db.run(
            `INSERT INTO files (id, filename, originalname, filepath, password_hash, expiry_type, expiry_time, download_count) VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
            [fileId, req.file.filename, req.file.originalname, req.file.path, passwordHash, expiry, expiryTime],
            (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Database saving error.' });
                }
                const downloadLink = `${req.protocol}://${req.get('host')}/download/${fileId}`;
                res.json({ success: true, link: downloadLink });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// 2. Fetch File Metadata (Before Download Verification)
app.get('/api/file/:id', (req, res) => {
    db.get(`SELECT id, originalname, password_hash, expiry_type, expiry_time FROM files WHERE id = ?`, [req.params.id], (err, file) => {
        if (err || !file) return res.status(404).json({ error: 'File not found or expired.' });
        
        res.json({
            id: file.id,
            originalname: file.originalname,
            passwordRequired: !!file.password_hash
        });
    });
});

// 3. File Download/Verification Route
app.post('/api/download/:id', (req, res) => {
    const fileId = req.params.id;
    const { password } = req.body;

    db.get(`SELECT * FROM files WHERE id = ?`, [fileId], async (err, file) => {
        if (err || !file) return res.status(404).json({ error: 'File not found or expired.' });

        // Check time-based expiry explicitly just in case cron hasn't swept it yet
        if (file.expiry_time && Date.now() > file.expiry_time) {
            if (fs.existsSync(file.filepath)) fs.unlinkSync(file.filepath);
            db.run(`DELETE FROM files WHERE id = ?`, [fileId]);
            return res.status(410).json({ error: 'File expired.' });
        }

        // Verify password if set
        if (file.password_hash) {
            if (!password) return res.status(401).json({ error: 'Password required.' });
            const match = await bcrypt.compare(password, file.password_hash);
            if (!match) return res.status(401).json({ error: 'Invalid password.' });
        }

        // Check file existence on file-system
        if (!fs.existsSync(file.filepath)) {
            db.run(`DELETE FROM files WHERE id = ?`, [fileId]);
            return res.status(404).json({ error: 'File physically missing from server.' });
        }

        // Update download count
        const newCount = file.download_count + 1;
        
        if (file.expiry_type === '1d') {
            // "After 1 download" -> Delete immediately
            res.download(file.filepath, file.originalname, (downloadErr) => {
                if (!downloadErr) {
                    if (fs.existsSync(file.filepath)) fs.unlinkSync(file.filepath);
                    db.run(`DELETE FROM files WHERE id = ?`, [fileId]);
                }
            });
        } else {
            // Standard update counter and trigger download
            db.run(`UPDATE files SET download_count = ? WHERE id = ?`, [newCount, fileId], () => {
                res.download(file.filepath, file.originalname);
            });
        }
    });
});

// --- ADMIN API ---

// 4. Admin Login and Management Route
app.post('/api/admin/dashboard', (req, res) => {
    const { username, password } = req.body;
    if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
        return res.status(403).json({ error: 'Unauthorized Access. Invalid Admin Credentials.' });
    }

    db.all(`SELECT id, originalname, expiry_type, download_count FROM files`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database fetch failure.' });
        res.json({ success: true, files: rows });
    });
});

// 5. Admin Direct Delete Route
app.post('/api/admin/delete', (req, res) => {
    const { username, password, fileId } = req.body;
    if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
        return res.status(403).json({ error: 'Unauthorized Access.' });
    }

    db.get(`SELECT * FROM files WHERE id = ?`, [fileId], (err, file) => {
        if (err || !file) return res.status(404).json({ error: 'File record not found.' });

        if (fs.existsSync(file.filepath)) {
            fs.unlinkSync(file.filepath);
        }

        db.run(`DELETE FROM files WHERE id = ?`, [fileId], (deleteErr) => {
            if (deleteErr) return res.status(500).json({ error: 'Failed to delete entry.' });
            res.json({ success: true, message: 'File manually purged by Admin successfully.' });
        });
    });
});

// Fallback HTML router for beautiful handling of dynamic clean routes
app.get('/download/:id', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware for Multer file size exceptions
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large! Maximum limit is 50MB.' });
        }
    }
    res.status(500).json({ error: err.message || 'Unknown Server Error' });
});

app.listen(PORT, () => {
    console.log(`Server running 24/7 at http://localhost:${PORT}`);
});