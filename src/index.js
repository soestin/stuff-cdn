import { handleLogin } from './auth';
import { 
    handleAdminList, 
    handleAdminUpload, 
    handleAdminDelete, 
    handleListUsers, 
    handleCreateUser, 
    handleDeleteUser, 
    handleUpdatePermissions,
    handleGetFileContent,
    handleSaveFileContent,
    handleChangePassword
} from './admin';
import { loginPage, adminDashboard } from './templates';

// Rate limiting configuration
const rateLimits = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = {
    'list': 30,
    'upload': 10,
    'delete': 5
};

export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const path = url.pathname.substring(1);
        const method = request.method;

        // Handle preflight OPTIONS requests (CORS)
        if (method === 'OPTIONS') {
            return handleOptionsRequest();
        }

        // Admin routes
        if (path.startsWith('admin')) {
            const adminPath = path.substring(6); // Remove 'admin/' prefix

            // Admin UI routes
            if (method === 'GET') {
                if (adminPath === '' || adminPath === 'dashboard') {
                    return new Response(adminDashboard(), {
                        headers: { 'Content-Type': 'text/html' }
                    });
                }
                if (adminPath === 'login') {
                    return new Response(loginPage(), {
                        headers: { 'Content-Type': 'text/html' }
                    });
                }
            }

            // Admin API routes
            switch (true) {
                case adminPath === 'login' && method === 'POST':
                    return addCorsHeaders(await handleLogin(request, env));
                case adminPath === 'list' && method === 'GET':
                    return addCorsHeaders(await handleAdminList(request, env));
                case adminPath === 'upload' && method === 'POST':
                    return addCorsHeaders(await handleAdminUpload(request, env));
                case adminPath.startsWith('delete/') && method === 'DELETE':
                    return addCorsHeaders(await handleAdminDelete(request, env, adminPath.substring(7)));
                case adminPath.startsWith('edit/') && method === 'GET':
                    return addCorsHeaders(await handleGetFileContent(request, env, adminPath.substring(5)));
                case adminPath.startsWith('save/') && method === 'POST':
                    return addCorsHeaders(await handleSaveFileContent(request, env, adminPath.substring(5)));
                case adminPath === 'change-password' && method === 'POST':
                    return addCorsHeaders(await handleChangePassword(request, env));
                case adminPath === 'users' && method === 'GET':
                    return addCorsHeaders(await handleListUsers(request, env));
                case adminPath === 'users/create' && method === 'POST':
                    return addCorsHeaders(await handleCreateUser(request, env));
                case adminPath === 'users/delete' && method === 'POST':
                    return addCorsHeaders(await handleDeleteUser(request, env));
                case adminPath === 'users/permissions' && method === 'POST':
                    return addCorsHeaders(await handleUpdatePermissions(request, env));
            }
            
            return addCorsHeaders(new Response('Not Found', { status: 404 }));
        }

        // Original CDN routes
        if (!path) {
            return addCorsHeaders(new Response('Error: No file specified', { status: 400 }));
        }

        switch (true) {
            case path.startsWith('list') && method === 'GET':
                return addCorsHeaders(await handleListRequest(request, env));
                
            case path.startsWith('upload') && method === 'POST':
                return addCorsHeaders(await handleUploadRequest(request, env, path.substring(7)));
                
            case path.startsWith('delete') && method === 'DELETE':
                return addCorsHeaders(await handleDeleteRequest(request, env, path.substring(7)));
                
            default:
                if (method === 'GET') {
                    return addCorsHeaders(await handleGetFileRequest(path, env));
                }
        }

        return addCorsHeaders(new Response('Method Not Allowed', { status: 405 }));
    },
};

// Enhanced rate limiting function
async function checkRateLimit(ip, operation) {
    const now = Date.now();
    const key = `${ip}:${operation}`;
    const limit = RATE_LIMIT_MAX_REQUESTS[operation] || 30;
    
    let rateData = rateLimits.get(key) || { count: 0, timestamp: now };
    
    if (now - rateData.timestamp > RATE_LIMIT_WINDOW) {
        rateData = { count: 0, timestamp: now };
    }
    
    if (rateData.count >= limit) {
        return false;
    }
    
    rateData.count++;
    rateLimits.set(key, rateData);
    return true;
}

// Enhanced CORS headers with security improvements
function addCorsHeaders(response) {
    response.headers.set('Access-Control-Allow-Origin', '*');
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    response.headers.set('Access-Control-Allow-Headers', 'x-api-key, Content-Type, X-Session-Id');
    response.headers.set('X-Content-Type-Options', 'nosniff');
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    return response;
}

// Handle OPTIONS requests for preflight CORS
function handleOptionsRequest() {
    return new Response(null, {
        headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'x-api-key, Content-Type, X-Session-Id',
        },
    });
}

// Timing-safe string comparison helper
async function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') {
        return false;
    }
    const aBytes = new TextEncoder().encode(a);
    const bBytes = new TextEncoder().encode(b);
    if (aBytes.length !== bBytes.length) {
        return false;
    }
    return crypto.subtle.timingSafeEqual?.(aBytes, bBytes) ?? 
           aBytes.every((byte, i) => byte === bBytes[i]);
}

// Original CDN route handlers
async function handleListRequest(request, env) {
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    if (!await checkRateLimit(ip, 'list')) {
        return new Response('Rate limit exceeded', { 
            status: 429,
            headers: { 'Retry-After': '60' }
        });
    }

    const apiKey = request.headers.get('x-api-key');
    if (!await timingSafeEqual(apiKey, env.API_KEY)) {
        return new Response('Unauthorized', { status: 401 });
    }

    const listResult = await env.STUFF_BUCKET.list();
    const files = listResult.objects.map((object) => object.key);
    return new Response(JSON.stringify(files), { headers: { 'Content-Type': 'application/json' } });
}

async function handleUploadRequest(request, env, filename) {
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    if (!await checkRateLimit(ip, 'upload')) {
        return new Response('Rate limit exceeded', { 
            status: 429,
            headers: { 'Retry-After': '60' }
        });
    }

    const apiKey = request.headers.get('x-api-key');
    if (!await timingSafeEqual(apiKey, env.API_KEY)) {
        return new Response('Unauthorized', { status: 401 });
    }

    if (!filename) {
        return new Response('File path is required', { status: 400 });
    }

    const body = await request.arrayBuffer();
    await env.STUFF_BUCKET.put(filename, body);
    return new Response(`File ${filename} uploaded successfully`, { status: 200 });
}

async function handleDeleteRequest(request, env, filename) {
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    if (!await checkRateLimit(ip, 'delete')) {
        return new Response('Rate limit exceeded', { 
            status: 429,
            headers: { 'Retry-After': '60' }
        });
    }

    const apiKey = request.headers.get('x-api-key');
    if (!await timingSafeEqual(apiKey, env.API_KEY)) {
        return new Response('Unauthorized', { status: 401 });
    }

    if (!filename) {
        return new Response('File path is required', { status: 400 });
    }

    await env.STUFF_BUCKET.delete(filename);
    return new Response(`File ${filename} deleted successfully`, { status: 200 });
}

async function handleGetFileRequest(path, env) {
    const object = await env.STUFF_BUCKET.get(path);
    
    if (!object) {
        return new Response(`Error: File '${path}' not found`, { status: 404 });
    }

    return new Response(object.body, {
        headers: { 'Content-Type': object.httpMetadata.contentType || 'application/octet-stream' },
    });
}

