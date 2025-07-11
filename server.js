const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const forge = require('node-forge');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer');

const app = express();
app.use(cors());
app.use(express.json());

// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/citizenship_images/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const imageFileFilter = (req, file, cb) => {
    if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/png') {
        cb(null, true);
    } else {
        // Set a custom error on the request to be handled by the route
        req.fileValidationError = 'Invalid file type. Only JPG and PNG images are allowed.';
        cb(null, false); // Reject file
    }
};

const upload = multer({ storage: storage, fileFilter: imageFileFilter });

// Create uploads directory if it doesn't exist
const fs = require('fs');
const uploadDir = 'uploads/citizenship_images/';
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir, { recursive: true });
}

app.use(express.static(path.join(__dirname, 'public')));
app.use('/admin', express.static(path.join(__dirname, 'public/admin')));
app.use('/voting', express.static(path.join(__dirname, 'public/voting')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const pool = new Pool({
    user: 'postgres',
    host: 'db',
    database: 'evoting',
    password: 'password',
    port: 5432
});

const JWT_SECRET = crypto.randomBytes(32).toString('hex');

const caKeyPair = forge.pki.rsa.generateKeyPair(2048);
const caCert = forge.pki.createCertificate();
caCert.publicKey = caKeyPair.publicKey;
caCert.serialNumber = '01';
caCert.validity.notBefore = new Date();
caCert.validity.notAfter = new Date();
caCert.validity.notAfter.setFullYear(caCert.validity.notBefore.getFullYear() + 10);
caCert.setSubject([{ name: 'commonName', value: 'Election CA' }]);
caCert.setIssuer([{ name: 'commonName', value: 'Election CA' }]);
caCert.sign(caKeyPair.privateKey, forge.md.sha256.create());

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).send('Access denied');
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send('Invalid token');
        req.user = user;
        next();
    });
};

const authenticateAdmin = (req, res, next) => {
    authenticateToken(req, res, () => {
        if (!req.user.is_admin) return res.status(403).send('Admin access required');
        next();
    });
};

app.post('/api/register', upload.single('citizenshipImage'), async (req, res) => {
    if (req.fileValidationError) {
        return res.status(400).send(req.fileValidationError);
    }

    const { name, email, password, voterID, publicKey } = req.body;
    const citizenshipImagePath = req.file ? req.file.path : null;

    if (!citizenshipImagePath) {
        // This case implies file was rejected by filter or not provided.
        // If fileValidationError is present, it's already handled.
        // If no file was provided at all:
        if (!req.fileValidationError) {
            return res.status(400).send('Citizenship image is required.');
        }
    }

    // Password validation
    if (!password || password.length < 8) {
        if (req.file) fs.unlinkSync(citizenshipImagePath); // Clean up uploaded file
        return res.status(400).send('Password must be at least 8 characters long.');
    }
    if (!/[A-Z]/.test(password)) {
        if (req.file) fs.unlinkSync(citizenshipImagePath); // Clean up uploaded file
        return res.status(400).send('Password must contain at least one uppercase letter.');
    }
    if (!/[0-9]/.test(password)) {
        if (req.file) fs.unlinkSync(citizenshipImagePath); // Clean up uploaded file
        return res.status(400).send('Password must contain at least one number.');
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+/.test(password)) {
        if (req.file) fs.unlinkSync(citizenshipImagePath); // Clean up uploaded file
        return res.status(400).send('Password must contain at least one special character.');
    }

    try {
        const spkiDer = Buffer.from(publicKey, 'base64');
        const publicKeyPem = forge.pki.publicKeyToPem(forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(spkiDer.toString('binary'))));
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO voters (name, email, password, voter_id, public_key, certificate_status, is_admin, citizenship_image_path, citizenship_image_status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (voter_id) DO NOTHING RETURNING *',
            [name, email, hashedPassword, voterID, publicKeyPem, 'pending', false, citizenshipImagePath, 'pending']
        );
        if (result.rowCount === 0) {
            // If insert failed, remove the uploaded file
            if (req.file) fs.unlinkSync(citizenshipImagePath);
            return res.status(400).send('Voter ID or email already exists');
        }
        res.status(201).send('Voter registered');
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).send(error.message);
    }
});

app.post('/api/admin/approve-citizenship-image', authenticateAdmin, async (req, res) => {
    const { voterID } = req.body;
    try {
        const result = await pool.query(
            "UPDATE voters SET citizenship_image_status = 'approved' WHERE voter_id = $1 AND is_admin = FALSE RETURNING *",
            [voterID]
        );
        if (result.rowCount === 0) return res.status(404).send('Voter not found or already an admin.');
        res.send('Citizenship image approved');
    } catch (error) {
        console.error('Citizenship image approval error:', error);
        res.status(500).send(error.message);
    }
});

app.post('/api/admin/reject-citizenship-image', authenticateAdmin, async (req, res) => {
    const { voterID } = req.body;
    try {
        const result = await pool.query(
            "UPDATE voters SET citizenship_image_status = 'rejected' WHERE voter_id = $1 AND is_admin = FALSE RETURNING *",
            [voterID]
        );
        if (result.rowCount === 0) return res.status(404).send('Voter not found or already an admin.');
        // Optionally, delete the image file from storage upon rejection
        // const voter = result.rows[0];
        // if (voter.citizenship_image_path) {
        //     fs.unlink(path.join(__dirname, voter.citizenship_image_path), (err) => {
        //         if (err) console.error('Error deleting rejected citizenship image:', err);
        //     });
        // }
        res.send('Citizenship image rejected');
    } catch (error) {
        console.error('Citizenship image rejection error:', error);
        res.status(500).send(error.message);
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM voters WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).send('Invalid email or password');
        const user = result.rows[0];
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) return res.status(401).send('Invalid email or password');
        const token = jwt.sign({ email: user.email, voterID: user.voter_id, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, voterID: user.voter_id });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM voters WHERE email = $1 AND is_admin = TRUE', [email]);
        if (result.rows.length === 0) return res.status(401).send('Invalid admin credentials');
        const admin = result.rows[0];
        const isValid = await bcrypt.compare(password, admin.password);
        if (!isValid) return res.status(401).send('Invalid admin credentials');
        const token = jwt.sign({ email: admin.email, voterID: admin.voter_id, is_admin: true }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/request-certificate', async (req, res) => {
    const { voterID } = req.body;
    try {
        const result = await pool.query(
            'UPDATE voters SET certificate_status = $1 WHERE voter_id = $2 AND certificate_status = $3 RETURNING *',
            ['requested', voterID, 'pending']
        );
        if (result.rowCount === 0) return res.status(400).send('Invalid voter or certificate already requested');
        await pool.query(
            'INSERT INTO certificate_requests (voter_id, request_date, status) VALUES ($1, $2, $3) ON CONFLICT (voter_id) DO NOTHING',
            [voterID, new Date(), 'pending']
        );
        res.send('Certificate request submitted');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/auth-challenge/:voterID', async (req, res) => {
    const { voterID } = req.params;
    try {
        const result = await pool.query('SELECT * FROM voters WHERE voter_id = $1', [voterID]);
        if (result.rows.length === 0) return res.status(404).send('Voter not found');
        if (result.rows[0].certificate_status !== 'approved') return res.status(400).send('Certificate not approved');
        if (result.rows[0].has_voted) return res.status(400).send('Already voted');
        const challenge = crypto.randomBytes(32).toString('hex');
        await pool.query('UPDATE voters SET challenge = $1 WHERE voter_id = $2', [challenge, voterID]);
        res.json({ challenge });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/authenticate', async (req, res) => {
    const { voterID, signature } = req.body;
    try {
        const result = await pool.query('SELECT * FROM voters WHERE voter_id = $1', [voterID]);
        if (result.rows.length === 0) return res.status(404).send('Voter not found');
        const { public_key, challenge } = result.rows[0];

        const publicKey = forge.pki.publicKeyFromPem(public_key);
        const md = forge.md.sha256.create();
        md.update(challenge);
        const verified = publicKey.verify(md.digest().bytes(), Buffer.from(signature, 'base64').toString('binary'));
        if (!verified) return res.status(401).send('Invalid signature');

        await pool.query('UPDATE voters SET challenge = NULL WHERE voter_id = $1', [voterID]);
        res.send('Authentication successful');
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(500).send(error.message);
    }
});

app.post('/api/cast-vote', authenticateToken, async (req, res) => {
    const { encryptedVote, aesKey, iv } = req.body;
    const voterID = req.user.voterID;
    try {
        if (!encryptedVote || !aesKey || !iv) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const voterResult = await pool.query('SELECT * FROM voters WHERE voter_id = $1', [voterID]);
        if (voterResult.rows.length === 0) {
            return res.status(404).json({ error: 'Voter not found' });
        }
        if (voterResult.rows[0].has_voted) {
            return res.status(400).json({ error: 'Already voted' });
        }

        const voteID = `VOTE_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
        const blockID = (await pool.query('SELECT COALESCE(MAX(block_id), 0) + 1 AS next_id FROM ledger')).rows[0].next_id;
        const previousBlock = await pool.query('SELECT hash FROM ledger ORDER BY block_id DESC LIMIT 1');
        const previousHash = previousBlock.rows.length ? previousBlock.rows[0].hash : '0';
        const timestamp = new Date();
        const hash = crypto.createHash('sha256').update(JSON.stringify({ voteID, encryptedVote, timestamp, previousHash })).digest('base64');

        await pool.query(
            'INSERT INTO votes (vote_id, voter_id, encrypted_vote, timestamp, aes_key, iv) VALUES ($1, $2, $3, $4, $5, $6)',
            [voteID, voterID, encryptedVote, timestamp, aesKey, iv]
        );

        await pool.query(
            'INSERT INTO ledger (block_id, vote_id, hash, previous_hash, timestamp) VALUES ($1, $2, $3, $4, $5)',
            [blockID, voteID, hash, previousHash, timestamp]
        );

        await pool.query('UPDATE voters SET has_voted = TRUE WHERE voter_id = $1', [voterID]);

        const receipt = { receiptID: voteID, timestamp, blockHash: hash };
        res.json({ receipt });
    } catch (error) {
        console.error('Vote casting error:', error);
        res.status(500).json({ error: error.message || 'Internal server error' });
    }
});

app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
    try {
        const voters = await pool.query('SELECT COUNT(*) FROM voters WHERE is_admin = FALSE');
        const votes = await pool.query('SELECT COUNT(*) FROM votes');
        const activeCerts = await pool.query('SELECT COUNT(*) FROM voters WHERE certificate_status = $1 AND is_admin = FALSE', ['approved']);
        const revokedCerts = await pool.query('SELECT COUNT(*) FROM voters WHERE certificate_status = $1 AND is_admin = FALSE', ['revoked']);
        res.json({
            totalVoters: parseInt(voters.rows[0].count),
            totalVotes: parseInt(votes.rows[0].count),
            activeCerts: parseInt(activeCerts.rows[0].count),
            revokedCerts: parseInt(revokedCerts.rows[0].count)
        });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/admin/pending-certificates', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT v.name, v.voter_id, v.citizenship_image_path, v.citizenship_image_status, cr.request_date FROM voters v JOIN certificate_requests cr ON v.voter_id = cr.voter_id WHERE cr.status = $1', ['pending']);
        res.json(result.rows);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/admin/approve-certificate', authenticateAdmin, async (req, res) => {
    const { voterID } = req.body;
    try {
        const voterResult = await pool.query('SELECT * FROM voters WHERE voter_id = $1 AND is_admin = FALSE', [voterID]);
        if (voterResult.rows.length === 0) return res.status(404).send('Voter not found');

        const publicKeyPem = voterResult.rows[0].public_key;
        let publicKey;
        try {
            publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
        } catch (error) {
            console.error('Invalid public key format for voter:', voterID, error);
            return res.status(400).send('Invalid public key format');
        }

        const cert = forge.pki.createCertificate();
        cert.publicKey = publicKey;
        cert.serialNumber = crypto.randomBytes(8).toString('hex');
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
        cert.setSubject([{ name: 'commonName', value: voterResult.rows[0].name }, { name: 'emailAddress', value: voterResult.rows[0].email }]);
        cert.setIssuer(caCert.subject.attributes);
        cert.sign(caKeyPair.privateKey, forge.md.sha256.create());

        await pool.query(
            'UPDATE voters SET certificate_status = $1, certificate = $2 WHERE voter_id = $3',
            ['approved', forge.pki.certificateToPem(cert), voterID]
        );
        await pool.query('UPDATE certificate_requests SET status = $1 WHERE voter_id = $2', ['approved', voterID]);
        res.send('Certificate approved');
    } catch (error) {
        console.error('Certificate approval error:', error);
        res.status(500).send(error.message);
    }
});

app.post('/api/admin/reject-certificate', authenticateAdmin, async (req, res) => {
    const { voterID } = req.body;
    try {
        await pool.query('UPDATE voters SET certificate_status = $1 WHERE voter_id = $2 AND is_admin = FALSE', ['rejected', voterID]);
        await pool.query('UPDATE certificate_requests SET status = $1 WHERE voter_id = $2', ['rejected', voterID]);
        res.send('Certificate rejected');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/admin/revoke-certificate', authenticateAdmin, async (req, res) => {
    const { voterID } = req.body;
    try {
        await pool.query('UPDATE voters SET certificate_status = $1 WHERE voter_id = $2 AND is_admin = FALSE', ['revoked', voterID]);
        res.send('Certificate revoked');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/admin/tally-votes', authenticateAdmin, async (req, res) => {
    try {
        const votes = await pool.query('SELECT encrypted_vote, aes_key, iv FROM votes');
        const results = {};
        for (const vote of votes.rows) {
            try {
                const aesKey = await crypto.webcrypto.subtle.importKey(
                    "raw",
                    Buffer.from(vote.aes_key, 'base64'),
                    { name: "AES-GCM" },
                    false,
                    ["decrypt"]
                );
                const decrypted = await crypto.webcrypto.subtle.decrypt(
                    { name: "AES-GCM", iv: Buffer.from(vote.iv, 'base64') },
                    aesKey,
                    Buffer.from(vote.encrypted_vote, 'base64')
                );
                const voteData = JSON.parse(new TextDecoder().decode(decrypted));
                results[voteData.candidate] = (results[voteData.candidate] || 0) + 1;
            } catch (error) {
                console.error('Error decrypting vote:', error);
            }
        }
        res.json(results);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/admin/publish-results', authenticateAdmin, async (req, res) => {
    try {
        const votes = await pool.query('SELECT encrypted_vote, aes_key, iv FROM votes');
        const results = {};
        for (const vote of votes.rows) {
            try {
                const aesKey = await crypto.webcrypto.subtle.importKey(
                    "raw",
                    Buffer.from(vote.aes_key, 'base64'),
                    { name: "AES-GCM" },
                    false,
                    ["decrypt"]
                );
                const decrypted = await crypto.webcrypto.subtle.decrypt(
                    { name: "AES-GCM", iv: Buffer.from(vote.iv, 'base64') },
                    aesKey,
                    Buffer.from(vote.encrypted_vote, 'base64')
                );
                const voteData = JSON.parse(new TextDecoder().decode(decrypted));
                results[voteData.candidate] = (results[voteData.candidate] || 0) + 1;
            } catch (error) {
                console.error('Error decrypting vote:', error);
            }
        }

        const blockID = (await pool.query('SELECT COALESCE(MAX(block_id), 0) + 1 AS next_id FROM ledger')).rows[0].next_id;
        const previousBlock = await pool.query('SELECT hash FROM ledger ORDER BY block_id DESC LIMIT 1');
        const previousHash = previousBlock.rows.length ? previousBlock.rows[0].hash : '0';
        const timestamp = new Date();
        const hash = crypto.createHash('sha256').update(JSON.stringify({ type: 'RESULTS', data: results, timestamp, previousHash })).digest('base64');

        await pool.query(
            'INSERT INTO ledger (block_id, type, data, hash, previous_hash, timestamp) VALUES ($1, $2, $3, $4, $5, $6)',
            [blockID, 'RESULTS', JSON.stringify(results), hash, previousHash, timestamp]
        );
        res.send('Results published');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/ledger', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM ledger ORDER BY block_id');
        res.json(result.rows);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/verify-vote/:receiptID', async (req, res) => {
    const { receiptID } = req.params;
    try {
        const voteResult = await pool.query('SELECT * FROM votes WHERE vote_id = $1', [receiptID]);
        if (voteResult.rows.length === 0) return res.status(404).send('Vote not found');
        const ledgerResult = await pool.query('SELECT * FROM ledger WHERE vote_id = $1', [receiptID]);
        if (ledgerResult.rows.length === 0) return res.status(404).send('Ledger entry not found');
        res.json({ vote: voteResult.rows[0], ledgerEntry: ledgerResult.rows[0] });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/verify-election', async (req, res) => {
    try {
        const votes = await pool.query('SELECT encrypted_vote, aes_key, iv FROM votes');
        let validVotes = 0;
        let invalidVotes = 0;
        for (const vote of votes.rows) {
            try {
                const aesKey = await crypto.webcrypto.subtle.importKey(
                    "raw",
                    Buffer.from(vote.aes_key, 'base64'),
                    { name: "AES-GCM" },
                    false,
                    ["decrypt"]
                );
                const decrypted = await crypto.webcrypto.subtle.decrypt(
                    { name: "AES-GCM", iv: Buffer.from(vote.iv, 'base64') },
                    aesKey,
                    Buffer.from(vote.encrypted_vote, 'base64')
                );
                validVotes++;
            } catch (error) {
                invalidVotes++;
            }
        }
        res.json({ validVotes, invalidVotes });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/verify-blockchain', async (req, res) => {
    try {
        const ledger = await pool.query('SELECT * FROM ledger ORDER BY block_id');
        let validBlocks = 0;
        let invalidBlocks = 0;
        for (let i = 0; i < ledger.rows.length; i++) {
            const block = ledger.rows[i];
            const expectedHash = crypto.createHash('sha256').update(JSON.stringify({
                block_id: block.block_id,
                vote_id: block.vote_id,
                type: block.type,
                data: block.data,
                previous_hash: block.previous_hash,
                timestamp: block.timestamp
            })).digest('base64');
            const isValid = expectedHash === block.hash && (i === 0 || block.previous_hash === ledger.rows[i-1].hash);
            if (isValid) validBlocks++;
            else invalidBlocks++;
        }
        res.json({ validBlocks, invalidBlocks });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

async function initializeDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS voters (
                voter_id VARCHAR(50) PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password TEXT NOT NULL,
                public_key TEXT NOT NULL,
                certificate_status VARCHAR(20) NOT NULL,
                certificate TEXT,
                has_voted BOOLEAN DEFAULT FALSE,
                challenge TEXT,
                is_admin BOOLEAN DEFAULT FALSE,
                citizenship_image_path TEXT,
                citizenship_image_status VARCHAR(20) DEFAULT 'pending'
            );
            CREATE TABLE IF NOT EXISTS certificate_requests (
                voter_id VARCHAR(50) PRIMARY KEY REFERENCES voters(voter_id),
                request_date TIMESTAMP NOT NULL,
                status VARCHAR(20) NOT NULL
            );
            CREATE TABLE IF NOT EXISTS votes (
                vote_id VARCHAR(50) PRIMARY KEY,
                voter_id VARCHAR(50) REFERENCES voters(voter_id),
                encrypted_vote TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                aes_key TEXT,
                iv TEXT
            );
            CREATE TABLE IF NOT EXISTS ledger (
                block_id SERIAL PRIMARY KEY,
                vote_id VARCHAR(50),
                type VARCHAR(20),
                data JSONB,
                hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL
            );
        `);

        const demoAdmin = await pool.query('SELECT * FROM voters WHERE email = $1', ['aayush@admin.com']);
        if (demoAdmin.rows.length === 0) {
            const keyPair = forge.pki.rsa.generateKeyPair(2048);
            const publicKeyPem = forge.pki.publicKeyToPem(keyPair.publicKey);
            const hashedPassword = await bcrypt.hash('adminadmin', 10);
            await pool.query(
                'INSERT INTO voters (voter_id, name, email, password, public_key, certificate_status, is_admin) VALUES ($1, $2, $3, $4, $5, $6, $7)',
                ['ADMIN_001', 'Admin User', 'aayush@admin.com', hashedPassword, publicKeyPem, 'approved', true]
            );
            console.log('Demo admin account created');
        }
    } catch (error) {
        console.error('Database initialization error:', error);
        process.exit(1);
    }
}

initializeDatabase().then(() => {
    app.listen(3000, () => {
        console.log('Server running on port 3000');
    });
});