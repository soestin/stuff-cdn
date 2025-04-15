export function loginPage() {
	return `<!DOCTYPE html>
	<html>
	<head>
		<title>CDN Admin Login</title>
		<style>
			body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
			.login-form { max-width: 400px; margin: 40px auto; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
			input { width: 100%; padding: 8px; margin: 8px 0; }
			button { width: 100%; padding: 10px; background: #0066ff; color: white; border: none; cursor: pointer; }
		</style>
	</head>
	<body>
		<div class="login-form">
			<h2>Admin Login</h2>
			<form id="loginForm">
				<input type="text" id="username" placeholder="Username" required>
				<input type="password" id="password" placeholder="Password" required>
				<button type="submit">Login</button>
			</form>
		</div>
		<script>
			document.getElementById('loginForm').onsubmit = async (e) => {
				e.preventDefault();
				const response = await fetch('/admin/login', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({
						username: document.getElementById('username').value,
						password: document.getElementById('password').value
					})
				});
				if (response.ok) {
					const { sessionId } = await response.json();
					localStorage.setItem('sessionId', sessionId);
					window.location.href = '/admin';
				} else {
					alert('Login failed');
				}
			};
		</script>
	</body>
	</html>`;
}

export function adminDashboard() {
    return `<!DOCTYPE html>
    <html>
    <head>
        <title>CDN Admin Dashboard</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.45.0/min/vs/loader.js"></script>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
            .container { max-width: 1200px; margin: 0 auto; }
            .section { margin: 20px 0; padding: 20px; background: #f5f5f5; border-radius: 4px; }
            .file-list { margin: 20px 0; }
            .file-item { display: flex; justify-content: space-between; padding: 10px; border-bottom: 1px solid #eee; }
            .user-item { background: white; padding: 15px; margin: 10px 0; border-radius: 4px; }
            .permissions-section { margin-top: 10px; }
            .tab-buttons { margin-bottom: 20px; }
            .tab-button { padding: 10px 20px; margin-right: 10px; border: none; background: #ddd; cursor: pointer; }
            .tab-button.active { background: #0066ff; color: white; }
            button { padding: 8px 16px; background: #0066ff; color: white; border: none; cursor: pointer; border-radius: 4px; }
            button.delete { background: #ff4444; }
            input, select { padding: 8px; margin: 4px 0; }
            .flex { display: flex; gap: 10px; align-items: center; }
            .hidden { display: none; }
            #editor-container { 
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0,0,0,0.8);
                display: none;
                z-index: 1000;
            }
            #editor-content {
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                width: 90%;
                height: 90%;
                background: white;
                border-radius: 8px;
                display: flex;
                flex-direction: column;
            }
            #editor-header {
                padding: 10px 20px;
                border-bottom: 1px solid #eee;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            #monaco-editor {
                flex-grow: 1;
                min-height: 500px;
            }
            .profile-section {
                margin-top: 20px;
                padding: 20px;
                background: #f5f5f5;
                border-radius: 4px;
            }
            .password-form {
                max-width: 400px;
            }
            .password-form input {
                width: 100%;
                margin-bottom: 10px;
            }
            .user-info {
                margin-bottom: 20px;
                padding: 10px;
                background: white;
                border-radius: 4px;
            }
            .logout-button {
                background: #ff4444;
                color: white;
                border: none;
                padding: 8px 16px;
                cursor: pointer;
                border-radius: 4px;
            }
            .loading-spinner {
                width: 50px;
                height: 50px;
                border: 5px solid #f3f3f3;
                border-top: 5px solid #0066ff;
                border-radius: 50%;
                animation: spin 1s linear infinite;
                margin: 20px auto;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            .loading-overlay {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(255, 255, 255, 0.8);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 9999;
            }
            .loading-overlay.hidden {
                display: none;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="tab-buttons" id="tabButtons">
                <button class="tab-button active" onclick="switchTab('files')">Files</button>
                <button class="tab-button" onclick="switchTab('profile')">Profile</button>
            </div>

            <div id="files-tab">
                <div class="section" id="uploadSection">
                    <h3>Upload File</h3>
                    <form id="uploadForm">
                        <input type="file" id="file" required>
                        <input type="text" id="filename" placeholder="Custom filename (optional)">
                        <button type="submit">Upload</button>
                    </form>
                </div>
                <div class="file-list" id="fileList">Loading...</div>
            </div>

            <div id="users-tab" class="hidden">
                <div class="section">
                    <h3>Create New User</h3>
                    <form id="createUserForm">
                        <div class="flex">
                            <input type="text" id="createUsername" placeholder="Username" required>
                            <input type="password" id="createPassword" placeholder="Password" required>
                            <button type="submit">Create User</button>
                        </div>
                    </form>
                </div>
                <div class="section">
                    <h3>User List</h3>
                    <div id="userList">Loading...</div>
                </div>
            </div>

            <div id="profile-tab" class="hidden">
                <div class="profile-section">
                    <h3>Your Profile</h3>
                    <div class="user-info">
                        <strong>Username: </strong><span id="current-username">Loading...</span>
                    </div>
                    <div class="password-form">
                        <h4>Change Password</h4>
                        <form id="changePasswordForm">
                            <input type="password" id="currentPassword" placeholder="Current Password" required>
                            <input type="password" id="changeNewPassword" placeholder="New Password" required>
                            <input type="password" id="confirmNewPassword" placeholder="Confirm New Password" required>
                            <button type="submit">Change Password</button>
                        </form>
                    </div>
                    <div style="margin-top: 20px;">
                        <button class="logout-button" onclick="logout()">Logout</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Editor Modal -->
        <div id="editor-container">
            <div id="editor-content">
                <div id="editor-header">
                    <h3 id="editor-filename"></h3>
                    <div>
                        <button onclick="saveFile()">Save</button>
                        <button onclick="closeEditor()" style="background: #999;">Close</button>
                    </div>
                </div>
                <div id="monaco-editor"></div>
            </div>
        </div>

        <!-- Permission Modal -->
        <div id="permissionModal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5);">
            <div style="background: white; padding: 20px; max-width: 500px; margin: 50px auto; border-radius: 4px;">
                <h3>Edit Permissions</h3>
                <div id="permissionForm">
                    <label>
                        <input type="checkbox" id="adminAccess"> Admin Access
                    </label>
                    <div>
                        <h4>File Patterns</h4>
                        <div id="patternList">
                            <div class="flex">
                                <input type="text" placeholder="*.jpg" class="pattern-input">
                                <button onclick="addPattern()" type="button">Add Pattern</button>
                            </div>
                        </div>
                    </div>
                    <div style="margin-top: 20px;">
                        <button onclick="savePermissions()">Save</button>
                        <button onclick="closePermissionModal()" style="background: #999;">Cancel</button>
                    </div>
                </div>
            </div>
        </div>

        <script>
            const sessionId = localStorage.getItem('sessionId');
            let currentUsername = '';
            let isAdmin = false;
            let userPermissions = {};
            let isLoading = false;
            
            if (!sessionId) {
                window.location.href = '/admin/login';
            }

            // Add loading overlay to the body
            const loadingOverlay = document.createElement('div');
            loadingOverlay.className = 'loading-overlay hidden';
            loadingOverlay.innerHTML = '<div class="loading-spinner"></div>';
            document.body.appendChild(loadingOverlay);

            function showLoading() {
                isLoading = true;
                loadingOverlay.classList.remove('hidden');
            }

            function hideLoading() {
                isLoading = false;
                loadingOverlay.classList.add('hidden');
            }

            // Initialize Monaco Editor
            require.config({ paths: { vs: 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.45.0/min/vs' }});
            require(['vs/editor/editor.main'], function() {
                editor = monaco.editor.create(document.getElementById('monaco-editor'), {
                    theme: 'vs',
                    automaticLayout: true
                });
            });

            // Initialize user permissions
            async function initializePermissions() {
                showLoading();
                try {
                    const response = await fetch('/admin/list', {
                        headers: { 'X-Session-Id': sessionId }
                    });
                    if (response.ok) {
                        const username = response.headers.get('X-Username');
                        if (username) {
                            currentUsername = username;
                            
                            // Fetch user permissions
                            const userResponse = await fetch('/admin/users', {
                                headers: { 'X-Session-Id': sessionId }
                            });
                            
                            if (userResponse.ok) {
                                const users = await userResponse.json();
                                const currentUser = users.find(user => user.username === username);
                                if (currentUser) {
                                    userPermissions = currentUser.permissions;
                                    isAdmin = userPermissions.admin === true;
                                    
                                    // Show/hide admin features
                                    updateUIBasedOnPermissions();
                                }
                            }
                        }
                    } else if (response.status === 401) {
                        window.location.href = '/admin/login';
                    }
                } catch (error) {
                    console.error('Failed to initialize permissions:', error);
                } finally {
                    hideLoading();
                }
            }

            function updateUIBasedOnPermissions() {
                // Show/hide user management tab
                const tabButtons = document.getElementById('tabButtons');
                if (isAdmin) {
                    tabButtons.innerHTML = \`
                        <button class="tab-button active" onclick="switchTab('files')">Files</button>
                        <button class="tab-button" onclick="switchTab('users')">User Management</button>
                        <button class="tab-button" onclick="switchTab('profile')">Profile</button>
                    \`;
                }

                // Show/hide upload section based on whether user has any upload permissions
                const uploadSection = document.getElementById('uploadSection');
                if (!isAdmin && (!userPermissions.patterns || userPermissions.patterns.length === 0)) {
                    uploadSection.style.display = 'none';
                }

                // Re-load current tab content
                const activeTab = document.querySelector('.tab-button.active');
                if (activeTab) {
                    switchTab(activeTab.textContent.toLowerCase().replace(' ', ''));
                }
            }

            function switchTab(tab) {
                // Only allow users tab for admins
                if (tab === 'users' && !isAdmin) {
                    return;
                }

                document.querySelectorAll('.tab-button').forEach(btn => {
                    btn.classList.toggle('active', btn.innerText.toLowerCase().includes(tab));
                });
                document.getElementById('files-tab').classList.toggle('hidden', tab !== 'files');
                document.getElementById('users-tab').classList.toggle('hidden', tab !== 'users');
                document.getElementById('profile-tab').classList.toggle('hidden', tab !== 'profile');

                if (tab === 'files') loadFiles();
                if (tab === 'users' && isAdmin) loadUsers();
                if (tab === 'profile') loadProfile();
            }

            // Modified loadFiles function to handle permissions
            async function loadFiles() {
                showLoading();
                try {
                    const response = await fetch('/admin/list', {
                        headers: { 'X-Session-Id': sessionId }
                    });
                    if (response.ok) {
                        const files = await response.json();
                        document.getElementById('fileList').innerHTML = files.map(file => \`
                            <div class="file-item">
                                <div>
                                    <a href="\${window.location.origin}/\${file.name}" target="_blank">
                                        \${file.name}
                                    </a>
                                    <small>(\${(file.size / 1024).toFixed(1)} KB)</small>
                                </div>
                                <div class="flex">
                                    \${file.hasPermission && isEditableFile(file.name) ? 
                                        \`<button onclick="editFile('\${file.name}')">Edit</button>\` : ''}
                                    \${file.hasPermission ? 
                                        \`<button onclick="deleteFile('\${file.name}')" class="delete">Delete</button>\` : ''}
                                </div>
                            </div>
                        \`).join('');
                    } else if (response.status === 401) {
                        window.location.href = '/admin/login';
                    }
                } catch (error) {
                    console.error('Failed to load files:', error);
                } finally {
                    hideLoading();
                }
            }

            function isEditableFile(filename) {
                const editableExtensions = [
                    '.txt', '.md', '.html', '.htm', '.css', '.js', '.json', 
                    '.xml', '.yaml', '.yml', '.ini', '.conf', '.cfg'
                ];
                return editableExtensions.some(ext => filename.toLowerCase().endsWith(ext));
            }

            async function editFile(filename) {
                currentEditingFile = filename;
                document.getElementById('editor-filename').textContent = filename;
                document.getElementById('editor-container').style.display = 'block';

                const response = await fetch(\`/admin/edit/\${filename}\`, {
                    headers: { 'X-Session-Id': sessionId }
                });

                if (response.ok) {
                    const { content, contentType } = await response.json();
                    const language = getMonacoLanguage(filename, contentType);
                    editor.getModel().setValue(content);
                    monaco.editor.setModelLanguage(editor.getModel(), language);
                } else {
                    alert('Failed to load file');
                    closeEditor();
                }
            }

            function getMonacoLanguage(filename, contentType) {
                const ext = filename.split('.').pop().toLowerCase();
                const map = {
                    'js': 'javascript',
                    'json': 'json',
                    'html': 'html',
                    'htm': 'html',
                    'css': 'css',
                    'md': 'markdown',
                    'xml': 'xml',
                    'yaml': 'yaml',
                    'yml': 'yaml',
                    'ini': 'ini',
                    'txt': 'plaintext'
                };
                return map[ext] || 'plaintext';
            }

            async function saveFile() {
                if (!currentEditingFile) return;
                
                const content = editor.getValue();
                const response = await fetch(\`/admin/save/\${currentEditingFile}\`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Session-Id': sessionId
                    },
                    body: JSON.stringify({ content })
                });

                if (response.ok) {
                    closeEditor();
                    loadFiles();
                } else {
                    alert('Failed to save file');
                }
            }

            function closeEditor() {
                document.getElementById('editor-container').style.display = 'none';
                currentEditingFile = null;
            }

            // Modified loadUsers function with loading state
            async function loadUsers() {
                showLoading();
                try {
                    const response = await fetch('/admin/users', {
                        headers: { 'X-Session-Id': sessionId }
                    });
                    if (response.ok) {
                        const users = await response.json();
                        document.getElementById('userList').innerHTML = users.map(user => \`
                            <div class="user-item" data-username="\${user.username}">
                                <div class="flex" style="justify-content: space-between;">
                                    <strong>\${user.username}</strong>
                                    <div>
                                        <button onclick='editPermissions("\${user.username}", \${JSON.stringify(user.permissions)})'>Edit Permissions</button>
                                        <button class="delete" onclick='deleteUser("\${user.username}")'>Delete User</button>
                                    </div>
                                </div>
                                <div class="permissions-section">
                                    <small>
                                        \${user.permissions.admin ? 'Admin Access' : ''}
                                        \${user.permissions.patterns ? 'Patterns: ' + user.permissions.patterns.join(', ') : ''}
                                    </small>
                                </div>
                            </div>
                        \`).join('');
                    } else {
                        const errorText = await response.text();
                        document.getElementById('userList').innerHTML = \`<div class="error">Failed to load users: \${errorText}</div>\`;
                    }
                } catch (error) {
                    document.getElementById('userList').innerHTML = \`<div class="error">Error loading users</div>\`;
                } finally {
                    hideLoading();
                }
            }

            let currentEditUser = null;

            function editPermissions(username, permissions) {
                currentEditUser = username;
                document.getElementById('adminAccess').checked = permissions.admin || false;
                const patternList = document.getElementById('patternList');
                patternList.innerHTML = '';

                // Add existing patterns
                if (permissions.patterns && Array.isArray(permissions.patterns)) {
                    permissions.patterns.forEach(pattern => {
                        const container = document.createElement('div');
                        container.className = 'flex';
                        container.innerHTML = \`
                            <input type="text" value="\${pattern}" class="pattern-input">
                            <button onclick="this.parentElement.remove()" type="button">Remove</button>
                        \`;
                        patternList.appendChild(container);
                    });
                }

                // Add the "new pattern" input
                const newPatternContainer = document.createElement('div');
                newPatternContainer.className = 'flex';
                newPatternContainer.innerHTML = \`
                    <input type="text" placeholder="*.jpg" class="pattern-input">
                    <button onclick="addPattern()" type="button">Add Pattern</button>
                \`;
                patternList.appendChild(newPatternContainer);
                
                document.getElementById('permissionModal').style.display = 'block';
            }

            function closePermissionModal() {
                document.getElementById('permissionModal').style.display = 'none';
                currentEditUser = null;
            }

            function addPattern() {
                const patternList = document.getElementById('patternList');
                const container = document.createElement('div');
                container.className = 'flex';
                container.innerHTML = \`
                    <input type="text" placeholder="*.jpg" class="pattern-input">
                    <button onclick="this.parentElement.remove()" type="button">Remove</button>
                \`;
                patternList.insertBefore(container, patternList.lastElementChild);
            }

            async function savePermissions() {
                if (!currentEditUser) return;
                
                showLoading();
                try {
                    const patterns = Array.from(document.querySelectorAll('.pattern-input'))
                        .map(input => input.value.trim())
                        .filter(pattern => pattern);
                    
                    const permissions = {
                        admin: document.getElementById('adminAccess').checked,
                        patterns
                    };

                    const response = await fetch('/admin/users/permissions', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Session-Id': sessionId
                        },
                        body: JSON.stringify({
                            username: currentEditUser,
                            permissions
                        })
                    });

                    let result;
                    const responseText = await response.text();
                    try {
                        result = JSON.parse(responseText);
                    } catch (e) {
                        console.error('Failed to parse response:', responseText);
                        throw new Error('Invalid server response');
                    }
                    
                    if (response.ok && result) {
                        // Update the UI immediately
                        const userItem = document.querySelector('[data-username="' + currentEditUser + '"]');
                        if (userItem) {
                            const permSection = userItem.querySelector('.permissions-section');
                            if (permSection) {
                                permSection.innerHTML = \`
                                    <small>
                                        \${permissions.admin ? 'Admin Access' : ''}
                                        \${permissions.patterns && permissions.patterns.length ? 'Patterns: ' + permissions.patterns.join(', ') : ''}
                                    </small>
                                \`;
                            }
                        }
                        closePermissionModal();
                        await loadUsers(); // Refresh the entire user list
                    } else {
                        throw new Error(result.error || 'Failed to update permissions');
                    }
                } catch (error) {
                    console.error('Permission update error:', error);
                    alert(error.message || 'Failed to update permissions');
                } finally {
                    hideLoading();
                }
            }

            async function deleteFile(filename) {
                if (!confirm('Are you sure you want to delete this file?')) return;
                const response = await fetch(\`/admin/delete/\${filename}\`, {
                    method: 'DELETE',
                    headers: { 'X-Session-Id': sessionId }
                });
                if (response.ok) {
                    loadFiles();
                } else {
                    alert('Delete failed');
                }
            }

            // Modify deleteUser function to include loading state
            async function deleteUser(username) {
                if (!confirm('Are you sure you want to delete this user?')) return;
                
                showLoading();
                try {
                    const response = await fetch('/admin/users/delete', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Session-Id': sessionId
                        },
                        body: JSON.stringify({ username })
                    });

                    if (response.ok) {
                        await loadUsers(); // This already includes loading state
                    } else {
                        const errorText = await response.text();
                        alert(errorText || 'Failed to delete user');
                        hideLoading();
                    }
                } catch (error) {
                    alert('Failed to delete user');
                    hideLoading();
                }
            }

            document.getElementById('uploadForm').onsubmit = async (e) => {
                e.preventDefault();
                const formData = new FormData();
                formData.append('file', document.getElementById('file').files[0]);
                const customFilename = document.getElementById('filename').value;
                if (customFilename) {
                    formData.append('filename', customFilename);
                }
                
                const response = await fetch('/admin/upload', {
                    method: 'POST',
                    headers: { 'X-Session-Id': sessionId },
                    body: formData
                });
                
                if (response.ok) {
                    loadFiles();
                    document.getElementById('uploadForm').reset();
                } else {
                    alert('Upload failed');
                }
            };

            // Modify createUserForm submit handler to include loading state
            document.getElementById('createUserForm').onsubmit = async (e) => {
                e.preventDefault();
                showLoading();
                const username = document.getElementById('createUsername').value;
                const password = document.getElementById('createPassword').value;

                try {
                    const response = await fetch('/admin/users/create', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Session-Id': sessionId
                        },
                        body: JSON.stringify({ username, password })
                    });

                    if (response.ok) {
                        document.getElementById('createUserForm').reset();
                        await loadUsers(); // This already includes loading state
                    } else {
                        const errorText = await response.text();
                        alert(errorText || 'Failed to create user');
                        hideLoading();
                    }
                } catch (error) {
                    alert('Failed to create user');
                    hideLoading();
                }
            };

            async function loadProfile() {
                try {
                    const response = await makeAuthenticatedRequest('/admin/list');
                    if (response.ok) {
                        const username = response.headers.get('X-Username');
                        if (username) {
                            currentUsername = username;
                            document.getElementById('current-username').textContent = username;
                        }
                    }
                } catch (error) {
                    window.location.href = '/admin/login';
                }
            }

            document.getElementById('changePasswordForm').onsubmit = async (e) => {
                e.preventDefault();
                
                const currentPassword = document.getElementById('currentPassword').value;
                const newPassword = document.getElementById('changeNewPassword').value;
                const confirmPassword = document.getElementById('confirmNewPassword').value;

                if (newPassword !== confirmPassword) {
                    alert('New passwords do not match');
                    return;
                }

                try {
                    const response = await fetch('/admin/change-password', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Session-Id': sessionId
                        },
                        body: JSON.stringify({
                            currentPassword,
                            newPassword
                        })
                    });

                    const responseText = await response.text();
                    let errorMessage = responseText;
                    
                    try {
                        const jsonResponse = JSON.parse(responseText);
                        if (jsonResponse.error) {
                            errorMessage = jsonResponse.error;
                        }
                    } catch (e) {
                    }

                    if (response.ok) {
                        alert('Password changed successfully');
                        document.getElementById('changePasswordForm').reset();
                    } else {
                        alert(errorMessage || 'Failed to change password. Please try again.');
                    }
                } catch (error) {
                    alert('An error occurred while changing the password. Please try again.');
                }
            };

            function logout() {
                localStorage.removeItem('sessionId');
                window.location.href = '/admin/login';
            }

            async function makeAuthenticatedRequest(url, options = {}) {
                const headers = {
                    ...options.headers,
                    'X-Session-Id': sessionId
                };
                
                try {
                    const response = await fetch(url, { ...options, headers });
                    if (response.ok) {
                        const authHeader = response.headers.get('X-Username');
                        if (authHeader && !currentUsername) {
                            currentUsername = authHeader;
                            document.getElementById('current-username').textContent = currentUsername;
                        }
                        return response;
                    }
                    if (response.status === 401) {
                        window.location.href = '/admin/login';
                    }
                    throw new Error(await response.text());
                } catch (error) {
                    throw error;
                }
            }

            loadFiles();
            initializePermissions();
        </script>
    </body>
    </html>`;
}