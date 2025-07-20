import express from 'express';
import dotenv from 'dotenv';
import { pool } from './src/config/database_connection.js';
import cors from 'cors';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

// Define valid privileges for safety
const VALID_PRIVILEGES = [
  'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'INDEX',
  'ALTER', 'SHOW VIEW', 'LOCK TABLES', 'TRIGGER', 'EVENT', 'ALL PRIVILEGES'
];

// Define role-based privilege map
const ROLE_PRIVILEGES = {
  database_admin: ['ALL PRIVILEGES'],
  developer: ['SELECT', 'INSERT', 'UPDATE','CREATE'],
  analyst: ['SELECT', 'SHOW VIEW'],
  backup: ['SELECT', 'LOCK TABLES', 'SHOW VIEW', 'EVENT', 'TRIGGER'],
};

// Store user roles mapping (in production, this should be in a database)
const USER_ROLES = new Map();

// Function to get user role with fallback logic
const getUserRole = (username, privileges) => {
  // First check if we have a stored role
  const storedRole = USER_ROLES.get(username);
  if (storedRole) {
    return storedRole;
  }
  
  // Extract actual privileges from the grant strings
  const extractPrivileges = (grantStrings) => {
    const privs = new Set();
    grantStrings.forEach(grant => {
      if (grant.includes('GRANT')) {
        const match = grant.match(/GRANT\s+(.+?)\s+ON/);
        if (match) {
          const grantPrivs = match[1].split(',').map(p => p.trim().toUpperCase());
          grantPrivs.forEach(p => privs.add(p));
        }
      }
    });
    return Array.from(privs);
  };
  
  const userPrivs = extractPrivileges(privileges);
  
  // Check if this matches any custom role
  for (const [roleName, rolePrivs] of Object.entries(ROLE_PRIVILEGES)) {
    if (roleName !== 'database_admin' && roleName !== 'developer' && 
        roleName !== 'analyst' && roleName !== 'backup') {
      // This is a custom role, check if privileges match
      const hasAllPrivs = rolePrivs.every(priv => userPrivs.includes(priv));
      const hasSamePrivs = userPrivs.length === rolePrivs.length && hasAllPrivs;
      
      if (hasSamePrivs) {
        // Store this role for future use
        USER_ROLES.set(username, roleName);
        return roleName;
      }
    }
  }
  
  // Fallback to inference for built-in roles
  return inferRole(privileges);
};

// Infer user role based on privileges
const inferRole = (privileges) => {
  const joined = privileges.join(',').toLowerCase();

  if (joined.includes('all privileges')) return 'database_admin';
  if (joined.includes('lock tables') && joined.includes('trigger') && joined.includes('event')) return 'backup';
  if (joined.includes('insert') && joined.includes('update') && joined.includes('create')) return 'developer';
  if (joined.includes('select') && joined.includes('show view') && !joined.includes('insert') && !joined.includes('update') && !joined.includes('create')) return 'analyst';
  if (joined.includes('select') && !joined.includes('insert') && !joined.includes('update') && !joined.includes('create') && !joined.includes('drop')) return 'read_only';

  return 'unknown';
};

const sanitizePrivileges = (privStr) => {
  return privStr
    .split(',')
    .map(p => p.trim().toUpperCase())
    .filter(p => VALID_PRIVILEGES.includes(p));
};

// GET all users with inferred roles
app.get('/users', async (req, res) => {
  try {
    const [users] = await pool.query(`
      SELECT User, Host 
      FROM mysql.user 
      WHERE User NOT IN ('root', 'mysql.session', 'mysql.sys', 'debian-sys-maint') 
        AND Host IS NOT NULL AND Host != '' 
      ORDER BY User
    `);

    const usersWithPrivileges = await Promise.all(
      users.map(async (user) => {
        try {
          const [privileges] = await pool.query(`SHOW GRANTS FOR ??@??`, [user.User, user.Host]);
          const privStrings = privileges.map(p => Object.values(p)[0]);
          
          // Use the new getUserRole function
          const role = getUserRole(user.User, privStrings);
          
          return { username: user.User, host: user.Host, privileges: privStrings, role };
        } catch (err) {
          return { username: user.User, host: user.Host, privileges: [], role: 'unknown', error: err.message };
        }
      })
    );

    res.json(usersWithPrivileges);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users', details: err.message });
  }
});

// POST create a new user with role
app.post('/users', async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Missing required fields: username, password, role' });
  }

  const rolePrivs = ROLE_PRIVILEGES[role];
  if (!rolePrivs) {
    return res.status(400).json({ error: 'Invalid role specified' });
  }

  try {
    const escapedUsername = pool.escapeId(username);
    const escapedPassword = pool.escape(password);

    const createSQL = `CREATE USER ${escapedUsername}@'localhost' IDENTIFIED BY ${escapedPassword}`;
    await pool.query(createSQL);

    const grantSQL = `GRANT ${rolePrivs.join(', ')} ON *.* TO ${escapedUsername}@'localhost'`;
    await pool.query(grantSQL);

    // Store the user's assigned role
    USER_ROLES.set(username, role);

    res.json({ success: true, message: `User '${username}'@'localhost' created with role '${role}'` });
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ error: 'User creation failed', details: err.message });
  }
});

// DELETE user
app.delete('/users/:username', async (req, res) => {
  const { username } = req.params;

  try {
    // First, get the user's host from the database
    const [users] = await pool.query("SELECT Host FROM mysql.user WHERE User = ?", [username]);
    
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Delete the user with their actual host
    const host = users[0].Host;
    await pool.query("DROP USER ?@?", [username, host]);
    
    // Remove the user's role from our mapping
    USER_ROLES.delete(username);
    
    res.json({ success: true, message: `User '${username}'@'${host}' deleted successfully` });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ error: 'User deletion failed', details: err.message });
  }
});

// POST grant specific privileges
app.post('/grant', async (req, res) => {
  const { username, privilege, dbname, host = 'localhost' } = req.body;

  if (!username || !privilege || !dbname) {
    return res.status(400).json({ error: 'Missing required fields: username, privilege, dbname' });
  }

  const privList = sanitizePrivileges(privilege);
  if (!privList.length) {
    return res.status(400).json({ error: 'Invalid or unsupported privileges' });
  }

  try {
    await pool.query(`GRANT ${privList.join(', ')} ON ?? TO ??@?`, [`${dbname}.*`, username, host]);
    res.json({ success: true, message: `Granted ${privList.join(', ')} on ${dbname} to ${username}@${host}` });
  } catch (err) {
    res.status(500).json({ error: 'Grant failed', details: err.message });
  }
});

// POST create a custom role with privileges
app.post('/roles', async (req, res) => {
  const { roleName, privileges, description } = req.body;

  if (!roleName || !privileges || !Array.isArray(privileges) || privileges.length === 0) {
    return res.status(400).json({ error: 'Missing required fields: roleName and privileges array' });
  }

  const privList = privileges.filter(p => VALID_PRIVILEGES.includes(p));
  if (privList.length === 0) {
    return res.status(400).json({ error: 'No valid privileges provided' });
  }

  try {
    // Store role definition in a custom table or configuration
    // For now, we'll store it in a simple JSON file or add to ROLE_PRIVILEGES
    const roleDefinition = {
      name: roleName,
      privileges: privList,
      description: description || '',
      createdAt: new Date().toISOString()
    };

    // Add to the ROLE_PRIVILEGES object for immediate use
    ROLE_PRIVILEGES[roleName] = privList;

    res.json({ 
      success: true, 
      message: `Role '${roleName}' created with ${privList.length} privileges`,
      role: roleDefinition
    });
  } catch (err) {
    console.error('Error creating role:', err);
    res.status(500).json({ error: 'Role creation failed', details: err.message });
  }
});

// GET all custom roles
app.get('/roles', async (req, res) => {
  try {
    const customRoles = Object.entries(ROLE_PRIVILEGES)
      .filter(([roleName]) => !['database_admin', 'developer', 'analyst', 'backup'].includes(roleName))
      .map(([roleName, privileges]) => ({
        name: roleName,
        privileges: privileges,
        description: `Custom role with ${privileges.length} privileges`
      }));

    res.json(customRoles);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch roles', details: err.message });
  }
});

// POST assign role to existing user
app.post('/users/:username/role', async (req, res) => {
  const { username } = req.params;
  const { role } = req.body;

  if (!role) {
    return res.status(400).json({ error: 'Missing role parameter' });
  }

  // Check if the role exists
  if (!ROLE_PRIVILEGES[role]) {
    return res.status(400).json({ error: 'Invalid role specified' });
  }

  try {
    // Check if user exists
    const [users] = await pool.query("SELECT Host FROM mysql.user WHERE User = ?", [username]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Store the role assignment
    USER_ROLES.set(username, role);

    res.json({ 
      success: true, 
      message: `Role '${role}' assigned to user '${username}'`,
      user: username,
      role: role
    });
  } catch (err) {
    console.error('Error assigning role:', err);
    res.status(500).json({ error: 'Role assignment failed', details: err.message });
  }
});

// Debug route
app.get('/debug/users', async (req, res) => {
  try {
    const [users] = await pool.query(`
      SELECT User, Host 
      FROM mysql.user 
      WHERE User NOT IN ('root', 'mysql.session', 'mysql.sys', 'debian-sys-maint') 
      ORDER BY User
    `);
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users', details: err.message });
  }
});

// Debug route for role detection
app.get('/debug/roles', async (req, res) => {
  try {
    const [users] = await pool.query(`
      SELECT User, Host 
      FROM mysql.user 
      WHERE User NOT IN ('root', 'mysql.session', 'mysql.sys', 'debian-sys-maint') 
        AND Host IS NOT NULL AND Host != '' 
      ORDER BY User
    `);

    const usersWithRoles = await Promise.all(
      users.map(async (user) => {
        try {
          const [privileges] = await pool.query(`SHOW GRANTS FOR ??@??`, [user.User, user.Host]);
          const privStrings = privileges.map(p => Object.values(p)[0]);
          const role = getUserRole(user.User, privStrings);
          
          return { 
            username: user.User, 
            host: user.Host, 
            privileges: privStrings, 
            role,
            storedRole: USER_ROLES.get(user.User),
            availableRoles: Object.keys(ROLE_PRIVILEGES)
          };
        } catch (err) {
          return { 
            username: user.User, 
            host: user.Host, 
            privileges: [], 
            role: 'unknown', 
            error: err.message 
          };
        }
      })
    );

    res.json({
      users: usersWithRoles,
      customRoles: Object.entries(ROLE_PRIVILEGES)
        .filter(([roleName]) => !['database_admin', 'developer', 'analyst', 'backup'].includes(roleName))
        .map(([roleName, privileges]) => ({ name: roleName, privileges }))
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch debug info', details: err.message });
  }
});

app.get('/test-create', async (req, res) => {
    try {
      await pool.query(`CREATE USER IF NOT EXISTS 'testuser'@'localhost' IDENTIFIED BY 'testpass123'`);
      res.send('User created');
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: err.message });
    }
  });
  

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
