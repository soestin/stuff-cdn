// scripts/add_admin_user.js
import { hashPassword } from '../src/users.js';
import { execSync } from 'child_process';

const username = process.argv[2] || 'admin';
const password = process.argv[3] || 'changeme';

async function main() {
  const hashed = await hashPassword(password);
  // Store user
  execSync(`npx wrangler kv key put --binding=AUTH_STORE --preview false --remote user:${username} "${hashed}"`, { stdio: 'inherit' });
  // Store admin permissions
  execSync(`npx wrangler kv key put --binding=AUTH_STORE --preview false --remote perms:${username} '{"admin":true}'`, { stdio: 'inherit' });
  console.log(`Admin user '${username}' created.`);
}

main();