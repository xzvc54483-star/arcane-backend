const { spawn } = require('child_process');
const http = require('http');

const server = spawn('node', ['server.cjs'], { cwd: __dirname, shell: true });
let tested = false;

server.stdout.on('data', (data) => {
    const output = data.toString();
    process.stdout.write('[SERVER] ' + output);
    if (output.includes('running on port') && !tested) {
        tested = true;
        setTimeout(() => {
            const req = http.request({ hostname: 'localhost', port: 3000, path: '/api/generatekey', method: 'POST', headers: { 'Content-Type': 'application/json' } }, (res) => {
                let body = '';
                res.on('data', chunk => body += chunk);
                res.on('end', () => { console.log('RESPONSE:', body); server.kill(); process.exit(0); });
            });
            req.on('error', (e) => { console.error('REQ ERROR:', e); server.kill(); process.exit(1); });
            req.write(JSON.stringify({ days: 30 }));
            req.end();
        }, 1000);
    }
});

server.stderr.on('data', (data) => process.stderr.write('[ERR] ' + data));
server.on('close', () => process.exit(0));
setTimeout(() => { console.log('TIMEOUT'); server.kill(); process.exit(1); }, 10000);
