import { requireAuth } from './auth';
import { checkPermission, listUsers, createUser, deleteUser, updatePermissions, changePassword } from './users';

// Rate limiting map
const rateLimits = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const MAX_REQUESTS = 30; // 30 requests per minute

function checkRateLimit(ip) {
    const now = Date.now();
    const userRequests = rateLimits.get(ip) || [];
    
    // Clean up old requests
    const recentRequests = userRequests.filter(time => time > now - RATE_LIMIT_WINDOW);
    
    if (recentRequests.length >= MAX_REQUESTS) {
        return false;
    }
    
    recentRequests.push(now);
    rateLimits.set(ip, recentRequests);
    return true;
}

function sanitizeFileName(filename) {
    // Remove any path traversal attempts and normalize
    return filename.replace(/^\/+/, '').replace(/\.{2,}/g, '.');
}

// Remove ALLOWED_MIME_TYPES since we'll accept all types
const MIME_TYPE_MAP = {
    // Common image types
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg', 
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    
    // Document types
    '.pdf': 'application/pdf',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xls': 'application/vnd.ms-excel',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.ppt': 'application/vnd.ms-powerpoint',
    '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    
    // Text types
    '.txt': 'text/plain',
    '.csv': 'text/csv',
    '.md': 'text/markdown',
    '.html': 'text/html',
    '.htm': 'text/html',
    '.css': 'text/css',
    '.js': 'text/javascript',
    '.json': 'application/json',
    '.xml': 'application/xml',
    '.yaml': 'application/x-yaml',
    '.yml': 'application/x-yaml',
    
    // Archive types
    '.zip': 'application/zip',
    '.rar': 'application/x-rar-compressed',
    '.7z': 'application/x-7z-compressed',
    '.tar': 'application/x-tar',
    '.gz': 'application/gzip',
    
    // Audio types
    '.mp3': 'audio/mpeg',
    '.wav': 'audio/wav',
    '.ogg': 'audio/ogg',
    '.m4a': 'audio/mp4',
    
    // Video types
    '.mp4': 'video/mp4',
    '.webm': 'video/webm',
    '.avi': 'video/x-msvideo',
    '.mov': 'video/quicktime',
    '.wmv': 'video/x-ms-wmv',
    
    // Font types
    '.ttf': 'font/ttf',
    '.otf': 'font/otf',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.eot': 'application/vnd.ms-fontobject'
};

export async function handleAdminList(request, env) {
    try {
        const username = await requireAuth(request, env);
        const listResult = await env.STUFF_BUCKET.list();
        const files = await Promise.all(
            listResult.objects.map(async (object) => {
                const hasPermission = await checkPermission(username, object.key, env);
                if (!hasPermission) return null;
                return {
                    name: object.key,
                    size: object.size,
                    uploaded: object.uploaded,
                    type: object.httpMetadata?.contentType || 'application/octet-stream',
                    hasPermission: true
                };
            })
        );
        
        // Filter out null entries (files user doesn't have access to)
        const accessibleFiles = files.filter(file => file !== null);
        
        return new Response(JSON.stringify(accessibleFiles), {
            headers: { 
                'Content-Type': 'application/json',
                'X-Username': username,
                'Cache-Control': 'no-store'
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { 
            status: 401,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

export async function handleAdminUpload(request, env) {
    try {
        const username = await requireAuth(request, env);
        
        // Check file size
        const contentLength = parseInt(request.headers.get('content-length') || '0');
        if (contentLength > 50 * 1024 * 1024) { // 50MB limit
            return new Response(JSON.stringify({ error: 'File too large' }), { 
                status: 413,
                headers: { 
                    'Content-Type': 'application/json',
                    'Content-Security-Policy': "default-src 'none'",
                    'X-Content-Type-Options': 'nosniff'
                }
            });
        }

        const formData = await request.formData();
        const file = formData.get('file');
        let filename = formData.get('filename') || file.name;
        
        // Sanitize and validate filename
        filename = sanitizeFileName(filename);
        if (!filename || filename.includes('..')) {
            return new Response(JSON.stringify({ error: 'Invalid filename' }), { 
                status: 400,
                headers: { 
                    'Content-Type': 'application/json',
                    'Content-Security-Policy': "default-src 'none'",
                    'X-Content-Type-Options': 'nosniff'
                }
            });
        }

        // Validate file type
        const fileExtension = '.' + filename.split('.').pop().toLowerCase();
        const expectedMimeType = MIME_TYPE_MAP[fileExtension] || file.type || 'application/octet-stream';

        if (!file) {
            return new Response(JSON.stringify({ error: 'No file provided' }), { 
                status: 400,
                headers: { 
                    'Content-Type': 'application/json',
                    'Content-Security-Policy': "default-src 'none'",
                    'X-Content-Type-Options': 'nosniff'
                }
            });
        }

        if (!await checkPermission(username, filename, env)) {
            return new Response(JSON.stringify({ error: 'Permission denied' }), { 
                status: 403,
                headers: { 
                    'Content-Type': 'application/json',
                    'Content-Security-Policy': "default-src 'none'",
                    'X-Content-Type-Options': 'nosniff'
                }
            });
        }

        // Skip MIME type validation - accept all types
        const buffer = await file.arrayBuffer();
        await env.STUFF_BUCKET.put(filename, buffer, {
            httpMetadata: { 
                contentType: expectedMimeType,
                cacheControl: 'public, max-age=31536000',
            }
        });

        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { 
                'Content-Type': 'application/json',
                'Content-Security-Policy': "default-src 'none'",
                'X-Content-Type-Options': 'nosniff'
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { 
            status: 400,
            headers: { 
                'Content-Type': 'application/json',
                'Content-Security-Policy': "default-src 'none'",
                'X-Content-Type-Options': 'nosniff'
            }
        });
    }
}

export async function handleAdminDelete(request, env, filename) {
    try {
        const username = await requireAuth(request, env);
        
        if (!await checkPermission(username, filename, env)) {
            return new Response(JSON.stringify({ error: 'Permission denied' }), { 
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        await env.STUFF_BUCKET.delete(filename);
        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { 
            status: 401,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

// User management handlers
export async function handleListUsers(request, env) {
    try {
        const username = await requireAuth(request, env);
        const userPerms = await env.AUTH_STORE.get(`perms:${username}`);
        const permissions = JSON.parse(userPerms || '{}');
        
        if (!permissions.admin) {
            return new Response(JSON.stringify({ error: 'Admin access required' }), { 
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        
        const users = await listUsers(env);
        return new Response(JSON.stringify(users), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { 
            status: 401,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

export async function handleCreateUser(request, env) {
    try {
        const adminUser = await requireAuth(request, env);
        const adminPerms = await env.AUTH_STORE.get(`perms:${adminUser}`);
        const permissions = JSON.parse(adminPerms || '{}');
        
        if (!permissions.admin) {
            return new Response(JSON.stringify({ error: 'Admin access required' }), { 
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const { username, password } = await request.json();
        const result = await createUser(username, password, env);
        return new Response(JSON.stringify(result), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { 
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

export async function handleDeleteUser(request, env) {
    try {
        const adminUser = await requireAuth(request, env);
        const adminPerms = await env.AUTH_STORE.get(`perms:${adminUser}`);
        const permissions = JSON.parse(adminPerms || '{}');
        
        if (!permissions.admin) {
            return new Response(JSON.stringify({ error: 'Admin access required' }), { 
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const { username } = await request.json();
        const result = await deleteUser(username, env);
        return new Response(JSON.stringify(result), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { 
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

export async function handleUpdatePermissions(request, env) {
    try {
        const adminUser = await requireAuth(request, env);
        const adminPerms = await env.AUTH_STORE.get(`perms:${adminUser}`);
        const permissions = JSON.parse(adminPerms || '{}');
        
        if (!permissions.admin) {
            return new Response(JSON.stringify({ error: 'Admin access required' }), { 
                status: 403,
                headers: { 
                    'Content-Type': 'application/json'
                }
            });
        }

        const { username, permissions: newPermissions } = await request.json();
        const result = await updatePermissions(username, newPermissions, env);
        
        // Ensure we're sending a JSON response
        return new Response(JSON.stringify({ success: true, ...result }), {
            status: 200,
            headers: { 
                'Content-Type': 'application/json'
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({ 
            error: error.message || 'Failed to update permissions'
        }), { 
            status: 400,
            headers: { 
                'Content-Type': 'application/json'
            }
        });
    }
}

export async function handleChangePassword(request, env) {
    if (!checkRateLimit(request.headers.get('cf-connecting-ip'))) {
        return new Response(JSON.stringify({ error: 'Too many requests' }), { 
            status: 429,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    try {
        const username = await requireAuth(request, env);
        const body = await request.json();
        
        if (!body.currentPassword || !body.newPassword) {
            return new Response(JSON.stringify({ error: 'Missing password information' }), { 
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        await changePassword(username, body.currentPassword, body.newPassword, env);
        return new Response(JSON.stringify({ 
            success: true,
            message: 'Password changed successfully'
        }), {
            headers: { 
                'Content-Type': 'application/json',
                'X-Username': username,
                'Cache-Control': 'no-store'
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({ 
            error: error.message 
        }), { 
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

export async function handleGetFileContent(request, env, filename) {
    try {
        const username = await requireAuth(request, env);
        if (!await checkPermission(username, filename, env)) {
            return new Response(JSON.stringify({ error: 'Permission denied' }), { 
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const obj = await env.STUFF_BUCKET.get(filename);
        if (!obj) {
            return new Response(JSON.stringify({ error: 'File not found' }), { 
                status: 404,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const contentType = obj.httpMetadata?.contentType || 'application/octet-stream';
        // Only allow editing text-based files
        if (!isEditableFile(contentType, filename)) {
            return new Response(JSON.stringify({ error: 'File type not supported for editing' }), { 
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // Force text/plain for text files to ensure proper text handling
        const content = await obj.text();
        return new Response(JSON.stringify({
            content,
            contentType: 'text/plain'
        }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { 
            status: 401,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

export async function handleSaveFileContent(request, env, filename) {
    try {
        const username = await requireAuth(request, env);
        if (!await checkPermission(username, filename, env)) {
            return new Response(JSON.stringify({ error: 'Permission denied' }), { 
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const obj = await env.STUFF_BUCKET.get(filename);
        if (!obj) {
            return new Response(JSON.stringify({ error: 'File not found' }), { 
                status: 404,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const contentType = obj.httpMetadata?.contentType || 'application/octet-stream';
        if (!isEditableFile(contentType, filename)) {
            return new Response(JSON.stringify({ error: 'File type not supported for editing' }), { 
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const { content } = await request.json();
        await env.STUFF_BUCKET.put(filename, content, {
            httpMetadata: { contentType }
        });

        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { 
            status: 401,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

function isEditableFile(contentType, filename) {
    const editableTypes = [
        'text/plain',
        'text/markdown',
        'text/html',
        'text/css',
        'text/javascript',
        'application/json',
        'application/xml',
        'application/x-yaml',
    ];

    const editableExtensions = [
        '.txt', '.md', '.html', '.htm', '.css', '.js', '.json', 
        '.xml', '.yaml', '.yml', '.ini', '.conf', '.cfg'
    ];

    return editableTypes.includes(contentType) || 
           editableExtensions.some(ext => filename.toLowerCase().endsWith(ext));
}