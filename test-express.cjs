const express = require('express');
console.log('Express version:', require('express/package.json').version);
const app = express();
app.use(express.json());
app.post('/test', (req, res) => {
    console.log('req.body:', req.body);
    res.json(req.body);
});
const s = app.listen(3001, () => {
    const http = require('http');
    setTimeout(() => {
        const req = http.request({ hostname: 'localhost', port: 3001, path: '/test', method: 'POST', headers: { 'Content-Type': 'application/json' } }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => { console.log('Response:', data); s.close(); process.exit(0); });
        });
        req.on('error', (e) => { console.error('Error:', e); s.close(); process.exit(1); });
        req.write(JSON.stringify({ days: 30 }));
        req.end();
    }, 500);
});
