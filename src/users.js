export async function listUsers(env) {
    const userList = await env.AUTH_STORE.list({ prefix: 'user:' });
    const users = [];
    
    for (const key of userList.keys) {
        const username = key.name.replace('user:', '');
        const permissions = await env.AUTH_STORE.get(`perms:${username}`) || '{}';
        users.push({
            username,
            permissions: JSON.parse(permissions)
        });
    }
    
    return users;
}

async function hashPassword(password) {
    const encoder = new TextEncoder();
    // Add a random salt
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const data = encoder.encode(password + Array.from(salt).join(','));
    // Use a stronger hash algorithm with more iterations
    const key = await crypto.subtle.importKey(
        'raw',
        data,
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
    );
    const hash = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-512'
        },
        key,
        256
    );
    // Store both salt and hash
    return salt.toString() + ':' + Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function verifyPassword(password, storedHash) {
    const encoder = new TextEncoder();
    const [storedSalt, storedHashValue] = storedHash.split(':');
    const salt = storedSalt.split(',').map(Number);
    const data = encoder.encode(password + storedSalt);
    
    const key = await crypto.subtle.importKey(
        'raw',
        data,
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
    );
    
    const hash = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: new Uint8Array(salt),
            iterations: 100000,
            hash: 'SHA-512'
        },
        key,
        256
    );
    
    const hashHex = Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    
    return hashHex === storedHashValue;
}

export async function createUser(username, password, env) {
    // Input validation
    if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
        throw new Error('Invalid username or password format');
    }

    // Username format validation (alphanumeric + underscore, 3-32 chars)
    if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
        throw new Error('Username must be 3-32 characters and contain only letters, numbers, and underscores');
    }

    // Password strength validation (min 8 chars, at least 1 number and letter)
    if (password.length < 8 || !/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
        throw new Error('Password must be at least 8 characters and contain both letters and numbers');
    }

    const existingUser = await env.AUTH_STORE.get(`user:${username}`);
    if (existingUser) {
        throw new Error('User already exists');
    }
    
    const hashedPassword = await hashPassword(password);
    await env.AUTH_STORE.put(`user:${username}`, hashedPassword);
    await env.AUTH_STORE.put(`perms:${username}`, JSON.stringify({}));
    return { username };
}

export async function deleteUser(username, env) {
    await env.AUTH_STORE.delete(`user:${username}`);
    await env.AUTH_STORE.delete(`perms:${username}`);
    return { success: true };
}

export async function updatePermissions(username, permissions, env) {
    if (!username || typeof username !== 'string') {
        throw new Error('Invalid username');
    }

    // Validate permissions object structure
    if (!permissions || typeof permissions !== 'object') {
        throw new Error('Invalid permissions format');
    }

    // Validate patterns array if it exists
    if (permissions.patterns && !Array.isArray(permissions.patterns)) {
        throw new Error('Patterns must be an array');
    }

    // Validate each pattern
    if (permissions.patterns) {
        for (const pattern of permissions.patterns) {
            if (typeof pattern !== 'string' || pattern.includes('../') || pattern.startsWith('/')) {
                throw new Error('Invalid pattern format');
            }
        }
    }

    const user = await env.AUTH_STORE.get(`user:${username}`);
    if (!user) {
        throw new Error('User does not exist');
    }
    
    await env.AUTH_STORE.put(`perms:${username}`, JSON.stringify(permissions));
    return { username, permissions };
}

export async function checkPermission(username, filename, env) {
    const perms = await env.AUTH_STORE.get(`perms:${username}`);
    if (!perms) return false;
    
    const userPerms = JSON.parse(perms);
    // Admin has all permissions
    if (userPerms.admin) return true;
    
    // Check specific file permissions
    if (userPerms.files && userPerms.files[filename]) {
        return true;
    }
    
    // Check wildcard permissions (e.g., "*.jpg")
    if (userPerms.patterns) {
        for (const pattern of userPerms.patterns) {
            if (new RegExp('^' + pattern.replace(/\*/g, '.*') + '$').test(filename)) {
                return true;
            }
        }
    }
    
    return false;
}

export async function changePassword(username, currentPassword, newPassword, env) {
    if (!username || !currentPassword || !newPassword || 
        typeof username !== 'string' || 
        typeof currentPassword !== 'string' || 
        typeof newPassword !== 'string') {
        throw new Error('Invalid input format');
    }

    // Password strength validation
    if (newPassword.length < 8 || !/[A-Za-z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
        throw new Error('New password must be at least 8 characters and contain both letters and numbers');
    }

    const storedHash = await env.AUTH_STORE.get(`user:${username}`);
    if (!storedHash) {
        throw new Error('User does not exist');
    }
    
    const isValid = await verifyPassword(currentPassword, storedHash);
    if (!isValid) {
        throw new Error('Current password is incorrect');
    }
    
    const newPasswordHash = await hashPassword(newPassword);
    await env.AUTH_STORE.put(`user:${username}`, newPasswordHash);
    return { success: true };
}