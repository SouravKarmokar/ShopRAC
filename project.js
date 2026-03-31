const express  = require('express');
const cors     = require('cors');
const crypto   = require('crypto'); // Built-in Node module — no install needed

const project = express();
project.use(cors());
project.use(express.json());

// ════════════════════════════════════════════════════════════════
//  BLOCK 1 — IP ACCESS CONTROL
//  The very first wall. Runs before EVERY route, including login.
//  If your IP isn't on the allowed list, you can't even attempt login.
// ════════════════════════════════════════════════════════════════

const ALLOWED_IPS = [
    '127.0.0.1',      // localhost IPv4
    '::1',            // localhost IPv6
    '192.168.1.100',  // Example: trusted office machine
];

const BLOCKED_IPS = [
    '10.0.0.99',      // Example: permanently banned machine
];

const ipFilter = (req, res, next) => {
    next(); // open to all IPs — token auth + RAC handles security
};

project.use(ipFilter); // Applied globally — ALL routes go through this first

// ════════════════════════════════════════════════════════════════
//  BLOCK 2 — USER STORE
//  This is the server's source of truth for credentials.
//  The frontend NEVER sends a role — only a token. The server
//  resolves the role from this store internally.
//
//  In production: store in a database, hash passwords with bcrypt.
//  The shape would be the same, just fetched from DB instead.
// ════════════════════════════════════════════════════════════════

const USERS = [
    { id: 'john',  password: 'cust123',  name: 'John Mia',    role: 'customer'  },
    { id: 'sarah', password: 'crea456',  name: 'Sarah Karim', role: 'creator'   },
    { id: 'ali',   password: 'ins#789',  name: 'Ali Hasan',   role: 'inserter'  },
    { id: 'rina',  password: 'mgr$321',  name: 'Rina Akter',  role: 'manager'   },
    { id: 'mike',  password: 'adm!999',  name: 'Mike Admin',  role: 'admin'     },
];

// ════════════════════════════════════════════════════════════════
//  BLOCK 3 — SESSION STORE
//  When a user logs in successfully, we create a random token and
//  store it here. The token maps to the user's name and role.
//
//  sessions = {
//    "a3f9b2c1...": { userId: 'sarah', name: 'Sarah Karim', role: 'creator' },
//    "7e1d4a88...": { userId: 'mike',  name: 'Mike Admin',  role: 'admin'   },
//  }
//
//  Why tokens and not just sending the role in every request?
//  Because a token is something the SERVER issued — it can't be
//  faked by the client. A plain "role: admin" header CAN be faked.
// ════════════════════════════════════════════════════════════════

const sessions = {}; // In-memory store — resets when server restarts

function createSession(user) {
    // crypto.randomBytes(32) generates 32 random bytes → 64 hex chars
    // This is cryptographically random — practically impossible to guess
    const token = crypto.randomBytes(32).toString('hex');
    sessions[token] = {
        userId: user.id,
        name:   user.name,
        role:   user.role,
    };
    return token;
}

function getSession(token) {
    return sessions[token] || null; // Returns session data, or null if token is invalid/expired
}

function destroySession(token) {
    delete sessions[token];
}

// ════════════════════════════════════════════════════════════════
//  BLOCK 4 — ROLE CONFIG (The RAC Permission Table)
//  Unchanged in concept — maps each role to a list of allowed actions.
// ════════════════════════════════════════════════════════════════

const rolesConfig = {
    customer: ['view'],
    creator:  ['view', 'create'],
    inserter: ['view', 'create', 'insert'],
    manager:  ['view', 'create', 'insert', 'update', 'delete'],
    admin:    ['view', 'create', 'insert', 'update', 'delete', 'assign'],
};

// ════════════════════════════════════════════════════════════════
//  BLOCK 5 — RAC MIDDLEWARE (now token-aware)
//  This middleware now does TWO things in sequence:
//    Step A — Authenticate: Is this token real? Look it up in sessions{}.
//    Step B — Authorize:    Does this session's role allow the action?
//
//  If both pass, it attaches the session data to req.session so the
//  route handler can use it (e.g., to log who did what).
// ════════════════════════════════════════════════════════════════

const authorize = (action) => {
    return (req, res, next) => {

        // --- Step A: AUTHENTICATION ---
        // The frontend sends: Authorization: Bearer <token>
        // We split on the space to extract just the token string.
        const authHeader = req.headers['authorization'] || '';
        const token      = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

        if (!token) {
            return res.status(401).json({ error: 'Unauthorized: No token provided. Please log in.' });
        }

        const session = getSession(token);
        if (!session) {
            return res.status(401).json({ error: 'Unauthorized: Invalid or expired token. Please log in again.' });
        }

        // --- Step B: AUTHORIZATION (RAC check) ---
        const userRole = session.role;

        if (!rolesConfig[userRole] || !rolesConfig[userRole].includes(action)) {
            return res.status(403).json({
                error: `RAC Denied: '${session.name}' (${userRole}) cannot perform '${action}'.`
            });
        }

        // Both checks passed — attach session to request and proceed
        req.session = session;
        next();
    };
};

// ════════════════════════════════════════════════════════════════
//  BLOCK 6 — DATA STORE
// ════════════════════════════════════════════════════════════════

let bills = [
    { id: 1, item: 'Basmati Rice (5kg)',  price: 320.00, category: 'Grocery' },
    { id: 2, item: 'Soybean Oil (1L)',    price: 175.50, category: 'Grocery' },
    { id: 3, item: 'Lentils (1kg)',       price: 95.00,  category: 'Grocery' },
];

let nextId = 4;

// ════════════════════════════════════════════════════════════════
//  BLOCK 7 — AUTH ROUTES  (no authorize() middleware needed here)
//
//  POST /auth/login   — verify credentials, return token + user info
//  POST /auth/logout  — destroy session token
//
//  Note: /auth/login is still IP-filtered (ipFilter runs globally),
//  but does NOT need the authorize() middleware since the user
//  doesn't have a token yet — they're getting one.
// ════════════════════════════════════════════════════════════════

project.post('/auth/login', (req, res) => {
    const { userId, password } = req.body;

    if (!userId || !password) {
        return res.status(400).json({ error: 'userId and password are required.' });
    }

    // Find user — case-insensitive ID match, exact password match
    const user = USERS.find(
        u => u.id.toLowerCase() === userId.toLowerCase() && u.password === password
    );

    if (!user) {
        // Deliberately vague — don't tell the caller whether the ID or password was wrong
        return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const token = createSession(user);

    console.log(`  ✅ LOGIN: ${user.name} (${user.role}) — token issued`);

    res.json({
        token:       token,
        name:        user.name,
        role:        user.role,
        permissions: rolesConfig[user.role],
    });
});

project.post('/auth/logout', (req, res) => {
    const authHeader = req.headers['authorization'] || '';
    const token      = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (token && sessions[token]) {
        const name = sessions[token].name;
        destroySession(token);
        console.log(`  👋 LOGOUT: ${name}`);
        return res.json({ message: 'Logged out successfully.' });
    }

    res.json({ message: 'No active session to log out.' });
});

// ════════════════════════════════════════════════════════════════
//  BLOCK 8 — BILL ROUTES  (all protected by authorize())
//  Request flow for each: IP Filter → Token Auth → RAC Check → Handler
// ════════════════════════════════════════════════════════════════

// VIEW — customer+
project.get('/bill/view', authorize('view'), (req, res) => {
    res.json(bills);
});

// CREATE — creator+
project.post('/bill/create', authorize('create'), (req, res) => {
    const { item, price, category } = req.body;

    if (!item || !price) {
        return res.status(400).json({ error: 'item and price are required.' });
    }

    const newBill = {
        id:        nextId++,
        item:      item,
        price:     parseFloat(price),
        category:  category || 'General',
        createdBy: req.session.name, // We know WHO created it from the token
    };

    bills.push(newBill);
    console.log(`  📝 CREATE: Bill #${newBill.id} by ${req.session.name}`);
    res.status(201).json({ message: `Created: '${newBill.item}'`, bill: newBill });
});

// INSERT — inserter+
project.post('/bill/insert', authorize('insert'), (req, res) => {
    const { targetId, subItem, subPrice } = req.body;

    const parentBill = bills.find(b => b.id === parseInt(targetId));
    if (!parentBill) {
        return res.status(404).json({ error: `Bill #${targetId} not found.` });
    }

    if (!parentBill.items) parentBill.items = [];

    const newSubItem = {
        subId:       parentBill.items.length + 1,
        subItem:     subItem || 'Unnamed Item',
        subPrice:    parseFloat(subPrice) || 0,
        insertedBy:  req.session.name,
    };

    parentBill.items.push(newSubItem);
    console.log(`  📥 INSERT: Sub-item into Bill #${targetId} by ${req.session.name}`);
    res.status(201).json({ message: `Inserted into Bill #${targetId}`, item: newSubItem });
});

// UPDATE — manager+
project.put('/bill/update/:id', authorize('update'), (req, res) => {
    const targetId = parseInt(req.params.id);
    const { item, price, category } = req.body;

    const billIndex = bills.findIndex(b => b.id === targetId);
    if (billIndex === -1) {
        return res.status(404).json({ error: `Bill #${targetId} not found.` });
    }

    if (item)     bills[billIndex].item     = item;
    if (price)    bills[billIndex].price    = parseFloat(price);
    if (category) bills[billIndex].category = category;
    bills[billIndex].lastUpdatedBy = req.session.name;

    console.log(`  ✏️  UPDATE: Bill #${targetId} by ${req.session.name}`);
    res.json({ message: `Updated Bill #${targetId}`, bill: bills[billIndex] });
});

// DELETE — manager+
project.delete('/bill/delete/:id', authorize('delete'), (req, res) => {
    const targetId = parseInt(req.params.id);
    const before   = bills.length;

    bills = bills.filter(b => b.id !== targetId);

    if (bills.length === before) {
        return res.status(404).json({ error: `Bill #${targetId} not found.` });
    }

    console.log(`  🗑️  DELETE: Bill #${targetId} by ${req.session.name}`);
    res.json({ message: `Deleted Bill #${targetId}` });
});

// ASSIGN — admin only
project.post('/bill/assign', authorize('assign'), (req, res) => {
    const { username, newRole } = req.body;

    if (!username || !newRole) {
        return res.status(400).json({ error: 'username and newRole are required.' });
    }
    if (!rolesConfig[newRole]) {
        return res.status(400).json({ error: `'${newRole}' is not a valid role.` });
    }

    // In a real app: update the user's role in the database here.
    // We also invalidate their existing sessions so the new role takes effect immediately.
    for (const [tok, sess] of Object.entries(sessions)) {
        if (sess.userId === username) {
            destroySession(tok);
            console.log(`  🔄 Session invalidated for '${username}' after role reassignment`);
        }
    }

    console.log(`  🔑 ASSIGN: ${req.session.name} assigned '${newRole}' to '${username}'`);
    res.json({
        message:     `'${username}' is now a '${newRole}'.`,
        username:    username,
        newRole:     newRole,
        permissions: rolesConfig[newRole],
        note:        'Their existing sessions have been invalidated.',
    });
});

// ════════════════════════════════════════════════════════════════
//  BLOCK 9 — START SERVER
// ════════════════════════════════════════════════════════════════

project.listen(3000, () => {
    console.log('');
    console.log('  ┌─────────────────────────────────────────────┐');
    console.log('  │   ShopRAC API  →  http://localhost:3000      │');
    console.log('  ├─────────────────────────────────────────────┤');
    console.log('  │  🛡️  IP Filter        ACTIVE                 │');
    console.log('  │  🔐  Session Auth     ACTIVE                 │');
    console.log('  │  🔑  RAC Middleware   ACTIVE                 │');
    console.log('  ├─────────────────────────────────────────────┤');
    console.log('  │  POST   /auth/login         (public)         │');
    console.log('  │  POST   /auth/logout        (token)          │');
    console.log('  │  GET    /bill/view          customer+         │');
    console.log('  │  POST   /bill/create        creator+          │');
    console.log('  │  POST   /bill/insert        inserter+         │');
    console.log('  │  PUT    /bill/update/:id    manager+          │');
    console.log('  │  DELETE /bill/delete/:id    manager+          │');
    console.log('  │  POST   /bill/assign        admin only        │');
    console.log('  └─────────────────────────────────────────────┘');
    console.log('');
});
