// Add brute force protection
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_BLOCK_DURATION = 15 * 60 * 1000; // 15 minutes

async function hashPassword(password) {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const data = encoder.encode(password + Array.from(salt).join(','));
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
    return salt.toString() + ':' + Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function validateCredentials(username, password, env) {
    // Input validation
    if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
        throw new Error('Invalid credentials format');
    }

    const storedHash = await env.AUTH_STORE.get(`user:${username}`);
    if (!storedHash) return false;
    
    const [storedSalt, storedHashValue] = storedHash.split(':');
    if (!storedSalt || !storedHashValue) return false;

    const encoder = new TextEncoder();
    const salt = Uint8Array.from(storedSalt.split(',').map(Number));
    const data = encoder.encode(password + Array.from(salt).join(','));
    
    const key = await crypto.subtle.importKey(
        'raw',
        data,
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
    );
    
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-512'
        },
        key,
        256
    );

    const hashArray = Array.from(new Uint8Array(derivedBits));
    const passwordHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    return storedHashValue === passwordHash;
}

async function createSession(username, env) {
    const sessionId = crypto.randomUUID();
    const sessionData = JSON.stringify({
        username,
        created: Date.now(),
        lastRotated: Date.now(),
        userAgent: this.request?.headers.get('user-agent') || 'unknown'
    });
    
    // Invalidate any existing sessions for this user
    const existingSessions = await env.AUTH_STORE.list({ prefix: `session:` });
    for (const key of existingSessions.keys) {
        try {
            const data = await env.AUTH_STORE.get(key.name);
            const session = JSON.parse(data);
            if (session.username === username) {
                await env.AUTH_STORE.delete(key.name);
            }
        } catch (error) {
            // Skip invalid sessions
            continue;
        }
    }
    
    await env.AUTH_STORE.put(`session:${sessionId}`, sessionData, { 
        expirationTtl: 86400 // 24 hours
    });
    return sessionId;
}

async function validateSession(sessionId, env) {
    if (!sessionId) return null;

    try {
        const sessionData = await env.AUTH_STORE.get(`session:${sessionId}`);
        if (!sessionData) return null;

        const session = JSON.parse(sessionData);
        const username = session.username;
        const now = Date.now();
        
        // Check if user still exists
        const userExists = await env.AUTH_STORE.get(`user:${username}`);
        if (!userExists) {
            await env.AUTH_STORE.delete(`session:${sessionId}`);
            return null;
        }
        
        // Rotate session if it's older than 1 hour
        if (now - session.lastRotated > 3600000) {
            const newSessionId = await rotateSession(sessionId, session, env);
            throw new Error('SESSION_ROTATION_NEEDED:' + newSessionId);
        }
        
        return username;
    } catch (error) {
        if (error.message?.startsWith('SESSION_ROTATION_NEEDED:')) {
            throw error; // Propagate session rotation errors
        }
        return null;
    }
}

async function rotateSession(oldSessionId, sessionData, env) {
    const newSessionId = crypto.randomUUID();
    const newSessionData = {
        ...JSON.parse(sessionData),
        lastRotated: Date.now()
    };
    
    await env.AUTH_STORE.put(`session:${newSessionId}`, JSON.stringify(newSessionData), {
        expirationTtl: 86400 // 24 hours
    });
    await env.AUTH_STORE.delete(`session:${oldSessionId}`);
    
    return newSessionId;
}

// Cleanup function to remove old login attempts
function cleanupLoginAttempts() {
    const now = Date.now();
    for (const [ip, data] of loginAttempts.entries()) {
        if (now - data.timestamp > LOGIN_BLOCK_DURATION) {
            loginAttempts.delete(ip);
        }
    }
}

export async function handleLogin(request, env) {
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    const now = Date.now();

    // Cleanup old attempts on each login request
    cleanupLoginAttempts();

    // Check if IP is blocked
    const attempts = loginAttempts.get(ip);
    if (attempts && attempts.count >= MAX_LOGIN_ATTEMPTS && now - attempts.timestamp < LOGIN_BLOCK_DURATION) {
        return new Response(JSON.stringify({ 
            error: 'Too many login attempts. Please try again later.' 
        }), {
            status: 429,
            headers: { 
                'Content-Type': 'application/json',
                'Retry-After': Math.ceil((LOGIN_BLOCK_DURATION - (now - attempts.timestamp)) / 1000)
            }
        });
    }

    try {
        const { username, password } = await request.json();
        
        if (!username || !password) {
            return new Response(JSON.stringify({ error: 'Missing credentials' }), { 
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const isValid = await validateCredentials(username, password, env);
        if (!isValid) {
            // Update failed attempts counter
            const currentAttempts = loginAttempts.get(ip) || { count: 0, timestamp: now };
            currentAttempts.count++;
            currentAttempts.timestamp = now;
            loginAttempts.set(ip, currentAttempts);

            return new Response(JSON.stringify({ error: 'Invalid credentials' }), { 
                status: 401,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // Reset attempts on successful login
        loginAttempts.delete(ip);

        const sessionId = await createSession.call({ request }, username, env);
        return new Response(JSON.stringify({ sessionId }), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-store, must-revalidate',
                'Pragma': 'no-cache',
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
            },
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: 'Login failed' }), { 
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

export async function requireAuth(request, env) {
    const sessionId = request.headers.get('X-Session-Id');
    try {
        const username = await validateSession(sessionId, env);
        if (!username) {
            throw new Error('Unauthorized');
        }
        return username;
    } catch (error) {
        if (error.message?.startsWith('SESSION_ROTATION_NEEDED:')) {
            const newSessionId = error.message.split(':')[1];
            const response = new Response('Session expired', { status: 401 });
            response.headers.set('X-New-Session-Id', newSessionId);
            throw response;
        }
        throw new Error('Unauthorized');
    }
}