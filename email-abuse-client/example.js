/**
 * Example usage of email-abuse-detection-client.
 * Start your FastAPI backend first (e.g. run_project.bat or uvicorn on port 8000).
 */

const { EmailAbuseClient } = require('./index.js');

async function main() {
  const client = new EmailAbuseClient({
    baseUrl: 'http://localhost:8000',
  });

  // 1. Health check
  const health = await client.health();
  console.log('Health:', health);

  // 2. Check registration (main middleware call)
  const check = await client.checkRegistration({
    email: 'test@gmail.com',
    phone: '+919876543210',
  });
  console.log('Check registration:', check);
  console.log('Allowed?', check.allowed, '—', check.message);

  // 3. Login and get stats (protected)
  try {
    const loginRes = await client.login('admin', 'gtedfe');
    const admin = client.withToken(loginRes.access_token);
    const stats = await admin.getStats();
    console.log('Stats:', stats);
  } catch (e) {
    console.log('Login/stats failed (expected if no backend):', e.message);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
