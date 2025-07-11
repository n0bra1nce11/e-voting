const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const forge = require('node-forge');
const crypto = require('crypto');

// Database connection configuration (same as server.js)
const pool = new Pool({
    user: 'postgres',
    host: 'db', // Assuming this script is run in an environment that can resolve 'db' (e.g., within docker-compose network)
    database: 'evoting',
    password: 'password',
    port: 5432
});

// --- Test Data Definitions ---

const NUM_TEST_VOTERS = 500;
const testUsersData = [];
const defaultPassword = "Password123!"; // Common password for all test users

for (let i = 1; i <= NUM_TEST_VOTERS; i++) {
    const paddedId = String(i).padStart(3, '0');
    testUsersData.push({
        voter_id: `TEST_VOTER_${paddedId}`,
        name: `Test User ${paddedId}`,
        email: `testuser${paddedId}@example.com`,
        password: defaultPassword,
        certificate_status: "approved", // To allow voting
        has_voted: false,
        is_admin: false,
        citizenship_image_path: `uploads/citizenship_images/test_user_${paddedId}.jpg`, // Placeholder
        citizenship_image_status: "approved" // To align with certificate status
    });
}

// Add a specific admin user if needed, separate from bulk voters
testUsersData.push({
    voter_id: "TEST_ADMIN_001",
    name: "Test Admin User",
    email: "testadmin1@example.com",
    password: "AdminPassword1#",
    certificate_status: "approved",
    has_voted: false,
    is_admin: true,
    citizenship_image_path: null,
    citizenship_image_status: "n/a" // Not applicable for admins
});


// testVotesData will be generated based on testUsersData.
const testVotesData = [];
const candidates = ["Candidate Alpha", "Candidate Bravo", "Candidate Charlie", "Candidate Delta"];

// Generate votes for all non-admin test users
for (let i = 0; i < NUM_TEST_VOTERS; i++) { // Only loop through the 500 generated voters
    const user = testUsersData[i];
    if (!user.is_admin) {
        testVotesData.push({
            voter_id: user.voter_id,
            candidateToVoteFor: candidates[i % candidates.length], // Distribute votes among candidates
            timestamp: new Date(Date.now() - (NUM_TEST_VOTERS - i) * 1000) // Stagger timestamps slightly
        });
    }
}


// --- Seeding Functions ---

async function generateKeyPair() {
    const keyPair = forge.pki.rsa.generateKeyPair(2048);
    const publicKeyPem = forge.pki.publicKeyToPem(keyPair.publicKey);
    // In a real scenario, you might store or use the private key, but for seeding voters, only public key is stored.
    return publicKeyPem;
}

async function seedUsers() {
    console.log('Seeding users...');
    for (const userData of testUsersData) {
        const hashedPassword = await bcrypt.hash(userData.password, 10);
        const publicKeyPem = await generateKeyPair();
        let certificate = null; // Placeholder, real cert generation is complex

        // If user is approved, we can generate a dummy certificate string
        if (userData.certificate_status === "approved") {
            certificate = `-----BEGIN CERTIFICATE-----\nMIIC...TEST_CERT_FOR_${userData.voter_id}...END CERTIFICATE-----`;
        }

        try {
            await pool.query(
                `INSERT INTO voters (voter_id, name, email, password, public_key, certificate_status, certificate, has_voted, is_admin, citizenship_image_path, citizenship_image_status)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 ON CONFLICT (voter_id) DO NOTHING`,
                [
                    userData.voter_id, userData.name, userData.email, hashedPassword, publicKeyPem,
                    userData.certificate_status, certificate, userData.has_voted, userData.is_admin,
                    userData.citizenship_image_path, userData.citizenship_image_status
                ]
            );
            console.log(`User ${userData.name} (${userData.voter_id}) seeded or already exists.`);

            // If certificate status is 'pending' or 'requested', add to certificate_requests
            if (userData.certificate_status === 'pending' || userData.certificate_status === 'requested') {
                await pool.query(
                    'INSERT INTO certificate_requests (voter_id, request_date, status) VALUES ($1, $2, $3) ON CONFLICT (voter_id) DO NOTHING',
                    [userData.voter_id, new Date(), 'pending']
                );
                console.log(`Certificate request for ${userData.voter_id} seeded or already exists.`);
            }

        } catch (error) {
            console.error(`Error seeding user ${userData.name}:`, error.message);
        }
    }
    console.log('User seeding complete.');
}

// Helper for mock encryption (actual encryption is done client-side in the app)
function mockEncryptVote(voteData, publicKeyPem) {
    // For seeding, we don't need real client-side encryption.
    // We'll create placeholders for aes_key, iv, and encrypted_vote.
    // The important part for the 'votes' table is that these fields exist.
    // The actual encrypted content would be JSON like `{"candidate": "Candidate A"}`
    const aesKey = crypto.randomBytes(32).toString('base64'); // Mock AES key
    const iv = crypto.randomBytes(16).toString('base64'); // Mock IV
    const encryptedVote = Buffer.from(JSON.stringify(voteData)).toString('base64'); // Simple base64 encoding for placeholder
    return { encryptedVote, aesKey, iv };
}


async function seedVotesAndLedger() {
    console.log('Seeding votes and ledger entries...');
    let previousHash = '0'; // For the first block in this seed run

    // Get the latest block_id and hash if ledger isn't empty
    const lastBlockResult = await pool.query('SELECT hash, block_id FROM ledger ORDER BY block_id DESC LIMIT 1');
    if (lastBlockResult.rows.length > 0) {
        previousHash = lastBlockResult.rows[0].hash;
        console.log(`Continuing ledger from previous hash: ${previousHash}`);
    }


    for (const voteData of testVotesData) {
        const voteID = `VOTE_TEST_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
        const voter = await pool.query('SELECT public_key FROM voters WHERE voter_id = $1', [voteData.voter_id]);

        if (voter.rows.length === 0) {
            console.warn(`Voter ${voteData.voter_id} not found for vote. Skipping.`);
            continue;
        }

        // const publicKeyPem = voter.rows[0].public_key;
        // For test data, we'll just create mock encrypted data as the client usually does this.
        const { encryptedVote, aesKey, iv } = mockEncryptVote({ candidate: voteData.candidateToVoteFor } /*, publicKeyPem */);
        const timestamp = voteData.timestamp;

        try {
            // Insert into votes table
            await pool.query(
                'INSERT INTO votes (vote_id, voter_id, encrypted_vote, timestamp, aes_key, iv) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (vote_id) DO NOTHING',
                [voteID, voteData.voter_id, encryptedVote, timestamp, aesKey, iv]
            );
            console.log(`Vote ${voteID} for voter ${voteData.voter_id} seeded.`);

            // Create ledger entry
            // block_id is SERIAL
            const ledgerDataToHash = JSON.stringify({ voteID, encryptedVote, timestamp, previousHash }); // Simplified for consistency with server
            const currentHash = crypto.createHash('sha256').update(ledgerDataToHash).digest('base64');

            const ledgerResult = await pool.query(
                'INSERT INTO ledger (vote_id, hash, previous_hash, timestamp) VALUES ($1, $2, $3, $4) RETURNING block_id',
                [voteID, currentHash, previousHash, timestamp]
            );

            if(ledgerResult.rows.length > 0) {
                console.log(`Ledger entry for vote ${voteID} created with block_id ${ledgerResult.rows[0].block_id}. Hash: ${currentHash}`);
                previousHash = currentHash; // Update previousHash for the next iteration
            } else {
                console.log(`Ledger entry for vote ${voteID} potentially skipped due to conflict or error.`);
            }


            // Mark voter as has_voted
            await pool.query('UPDATE voters SET has_voted = TRUE WHERE voter_id = $1', [voteData.voter_id]);
            console.log(`Voter ${voteData.voter_id} marked as has_voted.`);

        } catch (error) {
            console.error(`Error seeding vote for ${voteData.voter_id}:`, error.message);
        }
    }
    console.log('Vote and ledger seeding complete.');
}

async function main() {
    try {
        await pool.connect();
        console.log('Connected to database.');

        // Check if tables exist (simple check, assumes initializeDatabase in server.js has run)
        const checkTable = await pool.query("SELECT to_regclass('public.voters')");
        if (!checkTable.rows[0].to_regclass) {
            console.error("Tables do not seem to exist. Please run the application server first to initialize the database.");
            process.exit(1);
        }

        await seedUsers();
        await seedVotesAndLedger();

        console.log('Test data seeding finished successfully.');

    } catch (error) {
        console.error('Error during seeding process:', error);
    } finally {
        await pool.end();
        console.log('Database connection closed.');
    }
}

main();
