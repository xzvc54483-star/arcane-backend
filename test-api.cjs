const http = require('http');
const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/api/generatekey',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
};
const req = http.request(options, (res) => {
    let data = '';
    res.on('data', chunk => data += chunk);
    res.on('end', () => console.log('Response:', data));
});
req.on('error', (e) => console.error('Error:', e));
req.write(JSON.stringify({ days: 30 }));
req.end();
