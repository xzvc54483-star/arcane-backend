require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, MessageFlags } = require('discord.js');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'arcane.db');

const sql = new Database(DB_FILE);

// Enable WAL mode for better concurrency
sql.pragma('journal_mode = WAL');
sql.pragma('foreign_keys = ON');

// Initialize JSON database fallback
function loadDB() {
    let data;
    if (!fs.existsSync(path.join(__dirname, 'db.json'))) {
        data = { keys: [], users: [], activationLogs: [], launchers: [] };
        fs.writeFileSync(path.join(__dirname, 'db.json'), JSON.stringify(data, null, 2));
        return data;
    }
    try {
        const raw = fs.readFileSync(path.join(__dirname, 'db.json'), 'utf-8');
        data = JSON.parse(raw);
    } catch (e) {
        data = { keys: [], users: [], activationLogs: [], launchers: [] };
    }
    if (!data.launchers) data.launchers = [];
    return data;
}

function saveDB(db) {
    fs.writeFileSync(path.join(__dirname, 'db.json'), JSON.stringify(db, null, 2));
}

// -------------------------------------------------------------------
// SQLite Table Initialization
// -------------------------------------------------------------------
function initDatabase() {
    try {
        console.log('[DB] Initializing SQLite tables...');
        sql.exec(`
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                durationDays INTEGER NOT NULL DEFAULT 30,
                used INTEGER DEFAULT 0,
                usedBy TEXT,
                usedAt TEXT,
                createdAt TEXT NOT NULL,
                createdBy TEXT
            )
        `);
        sql.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                hwid TEXT DEFAULT '',
                subExpiresAt TEXT,
                lifetime INTEGER DEFAULT 0,
                registeredAt TEXT NOT NULL
            )
        `);
        sql.exec(`
            CREATE TABLE IF NOT EXISTS activation_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT NOT NULL,
                username TEXT NOT NULL,
                key TEXT,
                ip TEXT,
                hwid TEXT,
                lifetime INTEGER DEFAULT 0,
                expiresAt TEXT,
                activatedAt TEXT NOT NULL
            )
        `);
        sql.exec(`
            CREATE TABLE IF NOT EXISTS launchers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                buildId TEXT UNIQUE NOT NULL,
                name TEXT,
                compiledAt TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                downloadCount INTEGER DEFAULT 0,
                activeSessions TEXT DEFAULT '[]'
            )
        `);
        console.log('[DB] All tables created.');

        // Check and migrate from db.json if tables are empty
        const keyCount = sql.prepare('SELECT COUNT(*) as count FROM keys').get().count;
        console.log('[DB] Keys table count:', keyCount);
        if (keyCount === 0) {
            const jsonDbPath = path.join(__dirname, 'db.json');
            console.log('[DB] db.json exists:', fs.existsSync(jsonDbPath));
            if (fs.existsSync(jsonDbPath)) {
                const jsonData = JSON.parse(fs.readFileSync(jsonDbPath, 'utf-8'));
                console.log('[DB] db.json loaded:', Object.keys(jsonData).length, 'tables');
                const insertKey = sql.prepare('INSERT INTO keys (code, durationDays, used, usedBy, usedAt, createdAt, createdBy) VALUES (?, ?, ?, ?, ?, ?, ?)');
                const insertUser = sql.prepare('INSERT INTO users (id, username, password, hwid, subExpiresAt, lifetime, registeredAt) VALUES (?, ?, ?, ?, ?, ?, ?)');
                const insertLog = sql.prepare('INSERT INTO activation_logs (event, username, key, ip, hwid, lifetime, expiresAt, activatedAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
                const insertLauncher = sql.prepare('INSERT INTO launchers (buildId, name, compiledAt, status, downloadCount, activeSessions) VALUES (?, ?, ?, ?, ?, ?)');
                const insertKeyTx = sql.transaction((keys) => { for (const k of keys) insertKey.run(k.code, k.durationDays, k.used ? 1 : 0, k.usedBy || null, k.usedAt || null, k.createdAt || null, k.createdBy || null); });
                const insertUserTx = sql.transaction((users) => { for (const u of users) insertUser.run(u.id, u.username, u.password, u.hwid || '', u.subExpiresAt || null, u.lifetime ? 1 : 0, u.registeredAt || null); });
                const insertLogTx = sql.transaction((logs) => { for (const l of logs) insertLog.run(l.event, l.username, l.key || null, l.ip || null, l.hwid || null, l.lifetime ? 1 : 0, l.expiresAt || null, l.activatedAt || null); });
                const insertLauncherTx = sql.transaction((launchers) => { for (const l of launchers) insertLauncher.run(l.buildId, l.name || null, l.compiledAt || null, l.status || 'active', l.downloadCount || 0, JSON.stringify(l.activeSessions || [])); });
                insertKeyTx(jsonData.keys || []);
                insertUserTx(jsonData.users || []);
                insertLogTx(jsonData.activationLogs || []);
                insertLauncherTx(jsonData.launchers || []);
                console.log('[DB] Migration from db.json complete.');
            }
        }
        console.log('[DB] Initialization done.');
    } catch (err) {
        console.error('[DB] initDatabase error:', err.message);
        throw err;
    }
}

initDatabase();

// Helper functions
function generateRandomKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = 'ARCANE-';
    for (let i = 0; i < 12; i++) {
        if (i > 0 && i % 4 === 0) result += '-';
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

function formatDate(iso) {
    if (!iso) return 'N/A';
    return new Date(iso).toLocaleString('pl-PL', { timeZone: 'Europe/Warsaw' });
}

function isAdmin(interaction) {
    const member = interaction.member;
    return member && member.roles && member.roles.cache
        ? member.roles.cache.has(process.env.ADMIN_ROLE_ID || "1348766448197304350")
        : false;
}

// -------------------------------------------------------------------
// API: Generate License Key
// -------------------------------------------------------------------
app.post('/api/generatekey', (req, res) => {
    const { days } = req.body;
    const durationDays = parseInt(days) || 30;

    const newKey = generateRandomKey();

    const insert = sql.prepare('INSERT INTO keys (code, durationDays, used, createdAt) VALUES (?, ?, 0, ?)');
    insert.run(newKey, durationDays, new Date().toISOString());

    console.log(`[KEY CREATED] Code: ${newKey} | Days: ${durationDays}`);
    return res.json({ success: true, key: newKey, days: durationDays });
});

// -------------------------------------------------------------------
// API: Register User Account
// -------------------------------------------------------------------
app.post('/api/register', async (req, res) => {
    const { username, password, key, hwid } = req.body;
    const userIP = (req.headers['x-forwarded-for'] || '').split(',')[0]?.trim() || req.ip || 'Unknown';

    if (!username || !password || !key) {
        return res.json({ success: false, message: "Username, password, and license key are required!" });
    }
    if (username.length < 3 || password.length < 3) {
        return res.json({ success: false, message: "Username and password must be at least 3 characters!" });
    }

    const db = loadDB();

    // Check if username already exists
    const existingUser = sql.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username);
    if (existingUser) {
        return res.json({ success: false, message: "Username is already taken!" });
    }

    // Verify key
    const targetKey = sql.prepare('SELECT * FROM keys WHERE code = ? AND used = 0').get(key);
    if (!targetKey) {
        return res.json({ success: false, message: "Invalid or already used license key!" });
    }

    // Mark key as used
    sql.prepare('UPDATE keys SET used = 1, usedBy = ?, usedAt = ? WHERE code = ?').run(username, new Date().toISOString(), key);

    // Calculate subscription expiration
    const now = new Date();
    const isLifetime = targetKey.durationDays === 0;
    const expiresAt = isLifetime ? null : new Date(now.getTime() + targetKey.durationDays * 24 * 60 * 60 * 1000);

    const hashedPassword = await bcrypt.hash(password, 10);

    // Add user
    const insertUser = sql.prepare('INSERT INTO users (username, password, hwid, subExpiresAt, lifetime, registeredAt) VALUES (?, ?, ?, ?, ?, ?)');
    insertUser.run(username, hashedPassword, hwid || '', isLifetime ? null : expiresAt.toISOString(), isLifetime ? 1 : 0, now.toISOString());

    // Activation Log
    const insertLog = sql.prepare('INSERT INTO activation_logs (event, username, key, ip, hwid, lifetime, expiresAt, activatedAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
    insertLog.run('LICENSE_ACTIVATED', username, key, userIP, hwid || 'Not provided', isLifetime ? 1 : 0, isLifetime ? 'LIFETIME' : expiresAt.toISOString(), now.toISOString());

    console.log(`[LICENSE ACTIVATED] User: ${username} | Key: ${key} | IP: ${userIP} | HWID: ${hwid || 'N/A'}`);
    return res.json({
        success: true,
        message: "Account registered successfully!",
        expiresAt: isLifetime ? null : expiresAt.toISOString(),
        lifetime: isLifetime
    });
});

// -------------------------------------------------------------------
// API: View Activation Logs
// -------------------------------------------------------------------
app.get('/api/logs', (req, res) => {
    const logs = sql.prepare('SELECT * FROM activation_logs ORDER BY id DESC LIMIT 50').all();
    return res.json({ success: true, total: logs.length, logs });
});

// -------------------------------------------------------------------
// API: Login User
// -------------------------------------------------------------------
app.post('/api/login', async (req, res) => {
    const { username, password, hwid } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Username and password are required!" });
    }

    const user = sql.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username);
    if (!user) {
        return res.json({ success: false, message: "User not found!" });
    }

    const passwordValid = await bcrypt.compare(password, user.password);
    if (!passwordValid) {
        return res.json({ success: false, message: "Invalid password!" });
    }

    // Check HWID binding
    if (user.hwid && hwid && user.hwid !== hwid) {
        return res.json({ success: false, message: "HWID mismatch! PC not authorized." });
    }

    // Bind HWID if first login
    if (!user.hwid && hwid) {
        sql.prepare('UPDATE users SET hwid = ? WHERE id = ?').run(hwid, user.id);
    }

    // Check Subscription Expiration
    const now = new Date();

    if (user.lifetime) {
        return res.json({ success: true, message: "Login successful!", username: user.username, expiresAt: null, lifetime: true, daysLeft: -1, hoursLeft: -1 });
    }

    if (!user.subExpiresAt) {
        return res.json({ success: false, message: "Subscription EXPIRED! Buy new license.", expired: true });
    }

    const subDate = new Date(user.subExpiresAt);
    if (now > subDate) {
        return res.json({ success: false, message: "Subscription EXPIRED! Buy new license.", expired: true });
    }

    const diffMs = subDate - now;
    const daysLeft = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    const hoursLeft = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));

    console.log(`[LOGIN SUCCESS] User: ${username} | Sub Left: ${daysLeft}d ${hoursLeft}h`);
    return res.json({ success: true, message: "Login successful!", username: user.username, expiresAt: user.subExpiresAt, lifetime: false, daysLeft: daysLeft, hoursLeft: hoursLeft });
});

// -------------------------------------------------------------------
// API: Launcher Check Status
// -------------------------------------------------------------------
app.post('/api/launcher/check-status', (req, res) => {
    const { buildId, hwid } = req.body;
    if (!buildId) {
        return res.json({ success: false, destruct: false, message: "buildId is required" });
    }

    let launcher = sql.prepare('SELECT * FROM launchers WHERE LOWER(buildId) = LOWER(?)').get(buildId);

    if (!launcher) {
        launcher = {
            buildId: buildId,
            name: `Arcane Launcher ${buildId}`,
            compiledAt: new Date().toISOString(),
            status: "active",
            downloadCount: 1,
            activeSessions: hwid ? [hwid] : []
        };
        const insert = sql.prepare('INSERT INTO launchers (buildId, name, compiledAt, status, downloadCount, activeSessions) VALUES (?, ?, ?, ?, ?, ?)');
        insert.run(launcher.buildId, launcher.name, launcher.compiledAt, launcher.status, launcher.downloadCount, JSON.stringify(launcher.activeSessions));
    } else {
        if (hwid) {
            const sessions = JSON.parse(launcher.activeSessions || '[]');
            if (!sessions.includes(hwid)) {
                sessions.push(hwid);
                sql.prepare('UPDATE launchers SET activeSessions = ?, downloadCount = ? WHERE id = ?').run(JSON.stringify(sessions), sessions.length, launcher.id);
            }
        }
    }

    const isDestructed = launcher.status === 'destructed';
    return res.json({ success: true, buildId: launcher.buildId, status: launcher.status, destruct: isDestructed, message: isDestructed ? "Launcher build has been remotely destructed!" : "Build active" });
});

// -------------------------------------------------------------------
// API: Register Compiled Launcher Build
// -------------------------------------------------------------------
app.post('/api/launcher/register', (req, res) => {
    const { buildId, name } = req.body;
    if (!buildId) return res.json({ success: false, message: "buildId is required" });

    let launcher = sql.prepare('SELECT * FROM launchers WHERE LOWER(buildId) = LOWER(?)').get(buildId);
    if (launcher) {
        sql.prepare('UPDATE launchers SET name = ?, status = ? WHERE buildId = ?').run(name || launcher.name, 'active', buildId);
    } else {
        const insert = sql.prepare('INSERT INTO launchers (buildId, name, compiledAt, status, downloadCount, activeSessions) VALUES (?, ?, ?, ?, ?, ?)');
        insert.run(buildId, name || `Arcane Launcher ${buildId}`, new Date().toISOString(), 'active', 0, '[]');
    }

    return res.json({ success: true, message: `Launcher ${buildId} registered successfully.` });
});

// -------------------------------------------------------------------
// API: Renew License
// -------------------------------------------------------------------
app.post('/api/renew', async (req, res) => {
    const { username, key, hwid } = req.body;

    // Verify key
    const targetKey = sql.prepare('SELECT * FROM keys WHERE code = ? AND used = 0').get(key);
    if (!targetKey) {
        return res.json({ success: false, message: "Invalid or already used license key!" });
    }

    const user = sql.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username);
    if (!user) {
        return res.json({ success: false, message: "User not found!" });
    }

    const durationDays = targetKey.durationDays;
    const now = new Date();
    const isLifetime = durationDays === 0;
    const expiresAt = isLifetime ? null : new Date(now.getTime() + durationDays * 24 * 60 * 60 * 1000);

    sql.prepare('UPDATE users SET subExpiresAt = ?, lifetime = ? WHERE id = ?').run(isLifetime ? null : expiresAt.toISOString(), isLifetime ? 1 : 0, user.id);
    sql.prepare('UPDATE keys SET used = 1, usedBy = ?, usedAt = ? WHERE code = ?').run(username, new Date().toISOString(), key);

    return res.json({ success: true, message: "License renewed successfully!" });
});

// -------------------------------------------------------------------
// Discord Bot Setup
// -------------------------------------------------------------------

const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || "";
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "";
const ADMIN_ROLE_ID = process.env.ADMIN_ROLE_ID || "1348766448197304350";

if (DISCORD_BOT_TOKEN) {
    const client = new Client({ intents: [GatewayIntentBits.Guilds] });

    client.once('clientReady', async () => {
        console.log(`[DISCORD BOT] Logged in as ${client.user.tag}`);

        if (DISCORD_CLIENT_ID) {
            const commands = [
                new SlashCommandBuilder().setName('generatekey').setDescription('🔑 Generuje nowy klucz licencji Arcane').addIntegerOption(o => o.setName('days').setDescription('Czas w dniach (0 = Lifetime)').setRequired(true).setMinValue(0)),
                new SlashCommandBuilder().setName('userinfo').setDescription('📋 Informacje o użytkowniku').addStringOption(o => o.setName('username').setDescription('Nazwa użytkownika').setRequired(true)),
                new SlashCommandBuilder().setName('resetuser').setDescription('🔄 Resetuje HWID użytkownika (zmiana PC)').addStringOption(o => o.setName('username').setDescription('Nazwa użytkownika').setRequired(true)),
                new SlashCommandBuilder().setName('deleteuser').setDescription('🗑️ Usuwa użytkownika z bazy').addStringOption(o => o.setName('username').setDescription('Nazwa użytkownika').setRequired(true)),
                new SlashCommandBuilder().setName('extendkey').setDescription('⏳ Przedłuża subskrypcję użytkownika').addStringOption(o => o.setName('username').setDescription('Nazwa użytkownika').setRequired(true)).addIntegerOption(o => o.setName('days').setDescription('Liczba dni do dodania').setRequired(true).setMinValue(1)),
                new SlashCommandBuilder().setName('listkeys').setDescription('📜 Lista wygenerowanych kluczy').addStringOption(o => o.setName('filter').setDescription('Filtr').addChoices({ name: 'Wszystkie', value: 'all' }, { name: 'Nieużyte', value: 'unused' }, { name: 'Użyte', value: 'used' })),
                new SlashCommandBuilder().setName('logs').setDescription('📊 Ostatnie aktywacje licencji'),
                new SlashCommandBuilder().setName('stats').setDescription('📈 Statystyki systemu Arcane'),
                new SlashCommandBuilder().setName('launchers').setDescription('🚀 Pokazuje listę skompilowanych launcherów oraz opcję destruct'),
                new SlashCommandBuilder().setName('destructlauncher').setDescription('💣 Zdalne zniszczenie launchera na wszystkich komputerach').addStringOption(o => o.setName('buildid').setDescription('ID wersji launchera (np. v1.0.0)').setRequired(true)),
                new SlashCommandBuilder().setName('addlauncher').setDescription('➕ Dodaje skompilowany launcher do bazy bota').addStringOption(o => o.setName('buildid').setDescription('ID wersji (np. v1.0.0)').setRequired(true)).addStringOption(o => o.setName('name').setDescription('Opis/Nazwa launchera').setRequired(false)),
                new SlashCommandBuilder().setName('users').setDescription('👥 Lista wszystkich użytkowników z bazy danych'),
            ].map(cmd => cmd.toJSON());

            const rest = new REST({ version: '10' }).setToken(DISCORD_BOT_TOKEN);
            try {
                await rest.put(Routes.applicationCommands(DISCORD_CLIENT_ID), { body: commands });
                console.log('[DISCORD BOT] All slash commands registered!');
            } catch (err) {
                console.error('[DISCORD BOT] Error registering commands:', err);
            }
        }
    });

    client.on('interactionCreate', async interaction => {
        if (interaction.isButton()) {
            if (!isAdmin(interaction)) {
                return interaction.reply({ content: '❌ **Brak uprawnień!** Ta komenda jest tylko dla adminów.', flags: MessageFlags.Ephemeral });
            }
            if (interaction.customId.startsWith('destruct_build_')) {
                await interaction.deferUpdate();
                const targetBuildId = interaction.customId.replace('destruct_build_', '');
                const launcher = sql.prepare('SELECT * FROM launchers WHERE LOWER(buildId) = LOWER(?)').get(targetBuildId);
                if (launcher) {
                    sql.prepare('UPDATE launchers SET status = ? WHERE buildId = ?').run('destructed', targetBuildId);
                    console.log(`[LAUNCHER DESTRUCTED] Build: ${targetBuildId} | By: ${interaction.user.tag}`);
                    await interaction.followUp({ content: `💣 **SYGNAŁ DESTRUCT WYSŁANY!**\nLauncher o Build ID \`${targetBuildId}\` został zdestruowany. Wszystkie pobrane instancje u użytkowników ulegną samozniszczeniu przy następnym połączeniu.`, flags: MessageFlags.Ephemeral });
                } else {
                    await interaction.followUp({ content: `❌ Nie znaleziono launchera o ID \`${targetBuildId}\`.`, flags: MessageFlags.Ephemeral });
                }
            }
            return;
        }

        if (!interaction.isChatInputCommand()) return;

        const cmd = interaction.commandName;

        if (!isAdmin(interaction)) {
            return interaction.reply({ content: '❌ **Brak uprawnień!** Ta komenda jest tylko dla adminów.', flags: MessageFlags.Ephemeral });
        }

        await interaction.deferReply({ flags: MessageFlags.Ephemeral });

        try {
            const now = new Date();

            // ── /generatekey ──
            if (cmd === 'generatekey') {
                const days = interaction.options.getInteger('days') ?? 30;
                const isLifetime = days === 0;
                const newKey = generateRandomKey();
                sql.prepare('INSERT INTO keys (code, durationDays, used, createdAt, createdBy) VALUES (?, ?, 0, ?, ?)').run(newKey, days, new Date().toISOString(), interaction.user.tag);
                console.log(`[KEY CREATED] ${newKey} | ${isLifetime ? 'LIFETIME' : days + 'd'} | By: ${interaction.user.tag}`);
                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle('⚡ Klucz Licencji Wygenerowany').setColor(isLifetime ? 0xFFD700 : 0x2898FA).addFields({ name: '🔑 Klucz', value: `\`\`\`${newKey}\`\`\`` }, { name: '⏰ Czas', value: isLifetime ? '♾️ LIFETIME' : `${days} dni`, inline: true }, { name: '👤 Przez', value: `<@${interaction.user.id}>`, inline: true }).setFooter({ text: 'Arcane Auth • Tylko ty widzisz tę wiadomość' }).setTimestamp()]});
            }

            // ── /userinfo ──
            else if (cmd === 'userinfo') {
                const username = interaction.options.getString('username');
                const user = sql.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username);
                if (!user) return interaction.editReply({ content: `❌ Użytkownik **${username}** nie istnieje.` });

                const daysLeft = user.lifetime ? '∞' : (() => { if (!user.subExpiresAt || now > new Date(user.subExpiresAt)) return '0'; return Math.floor((new Date(user.subExpiresAt) - now) / (1000 * 60 * 60 * 24)); })();
                const statusText = user.lifetime ? '♾️ LIFETIME' : (!user.subExpiresAt || now > new Date(user.subExpiresAt) ? '🔴 WYGASŁA' : `🟢 AKTYWNA (${daysLeft} dni)`);
                const logs = sql.prepare('SELECT * FROM activation_logs WHERE username = ? ORDER BY id DESC LIMIT 1').all(username);

                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle(`📋 Info o użytkowniku: ${user.username}`).setColor(0x2898FA).addFields({ name: '🖥️ HWID', value: user.hwid || 'Nie powiązano', inline: false }, { name: '🌐 IP', value: logs[0]?.ip || 'Brak danych', inline: true }, { name: '📅 Rejestracja', value: formatDate(user.registeredAt), inline: true }, { name: '⏰ Wygaśnięcie', value: user.lifetime ? '♾️ LIFETIME' : formatDate(user.subExpiresAt), inline: true }, { name: '📊 Status', value: statusText, inline: true }).setFooter({ text: 'Arcane Auth System' }).setTimestamp()]});
            }

            // ── /resetuser ──
            else if (cmd === 'resetuser') {
                const username = interaction.options.getString('username');
                const user = sql.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username);
                if (!user) return interaction.editReply({ content: `❌ Użytkownik **${username}** nie istnieje.` });
                const oldHwid = user.hwid || 'Brak';
                sql.prepare('UPDATE users SET hwid = "" WHERE id = ?').run(user.id);
                console.log(`[HWID RESET] User: ${username} | Old HWID: ${oldHwid} | By: ${interaction.user.tag}`);
                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle('🔄 HWID Zresetowany').setColor(0xFFA500).addFields({ name: '👤 Użytkownik', value: username, inline: true }, { name: '🖥️ Stary HWID', value: oldHwid, inline: true }, { name: '✅ Status', value: 'Użytkownik może zalogować się z nowego PC', inline: false }).setFooter({ text: `Reset przez ${interaction.user.tag}` }).setTimestamp()]});
            }

            // ── /deleteuser ──
            else if (cmd === 'deleteuser') {
                const username = interaction.options.getString('username');
                const user = sql.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username);
                if (!user) return interaction.editReply({ content: `❌ Użytkownik **${username}** nie istnieje.` });
                sql.prepare('DELETE FROM users WHERE id = ?').run(user.id);
                console.log(`[USER DELETED] User: ${username} | By: ${interaction.user.tag}`);
                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle('🗑️ Użytkownik Usunięty').setColor(0xFF4444).addFields({ name: '👤 Usunięty użytkownik', value: username, inline: true }, { name: '👮 Przez', value: interaction.user.tag, inline: true }).setFooter({ text: 'Arcane Auth System' }).setTimestamp()]});
            }

            // ── /extendkey ──
            else if (cmd === 'extendkey') {
                const username = interaction.options.getString('username');
                const days = interaction.options.getInteger('days');
                const user = sql.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username);
                if (!user) return interaction.editReply({ content: `❌ Użytkownik **${username}** nie istnieje.` });
                if (user.lifetime) return interaction.editReply({ content: `ℹ️ Użytkownik **${username}** ma już LIFETIME — nie można przedłużyć.` });
                const base = (user.subExpiresAt && new Date(user.subExpiresAt) > now) ? new Date(user.subExpiresAt) : now;
                const newExpiry = new Date(base.getTime() + days * 24 * 60 * 60 * 1000);
                sql.prepare('UPDATE users SET subExpiresAt = ? WHERE id = ?').run(newExpiry.toISOString(), user.id);
                console.log(`[SUB EXTENDED] User: ${username} | +${days} days | New expiry: ${newExpiry.toISOString()} | By: ${interaction.user.tag}`);
                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle('⏳ Subskrypcja Przedłużona').setColor(0x00CC66).addFields({ name: '👤 Użytkownik', value: username, inline: true }, { name: '➕ Dodano dni', value: `${days} dni`, inline: true }, { name: '📅 Nowe wygaśnięcie', value: formatDate(newExpiry.toISOString()), inline: false }).setFooter({ text: `Przedłużono przez ${interaction.user.tag}` }).setTimestamp()]});
            }

            // ── /listkeys ──
            else if (cmd === 'listkeys') {
                const filter = interaction.options.getString('filter') || 'all';
                let keys;
                if (filter === 'unused') keys = sql.prepare('SELECT * FROM keys WHERE used = 0 ORDER BY id DESC LIMIT 15').all();
                else if (filter === 'used') keys = sql.prepare('SELECT * FROM keys WHERE used = 1 ORDER BY id DESC LIMIT 15').all();
                else keys = sql.prepare('SELECT * FROM keys ORDER BY id DESC LIMIT 15').all();
                const lines = keys.map(k => `\`${k.code}\` • ${k.durationDays === 0 ? '♾️ LT' : `${k.durationDays}d`} • ${k.used ? '✅ ' + k.usedBy : '⬜ Nieużyty'}`);
                const allKeys = sql.prepare('SELECT COUNT(*) as count FROM keys').get().count;
                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle(`📜 Klucze licencji (${filter}) — ${keys.length} szt.`).setColor(0x7B68EE).setDescription(lines.length > 0 ? lines.join('\n') : 'Brak kluczy.').setFooter({ text: `Pokazuję max 15 najnowszych | Łącznie: ${allKeys}` }).setTimestamp()]});
            }

            // ── /logs ──
            else if (cmd === 'logs') {
                const logs = sql.prepare('SELECT * FROM activation_logs ORDER BY id DESC LIMIT 10').all();
                const lines = logs.map((l, i) => `**${i+1}.** \`${l.username}\` • \`${l.ip}\` • HWID: \`${(l.hwid || 'N/A').substring(0,12)}...\` • ${formatDate(l.activatedAt)}`);
                const total = sql.prepare('SELECT COUNT(*) as count FROM activation_logs').get().count;
                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle('📊 Ostatnie aktywacje licencji').setColor(0x2898FA).setDescription(lines.length > 0 ? lines.join('\n') : 'Brak logów.').setFooter({ text: `Łącznie aktywacji: ${total}` }).setTimestamp()]});
            }

            // ── /stats ──
            else if (cmd === 'stats') {
                const totalUsers = sql.prepare('SELECT COUNT(*) as count FROM users').get().count;
                const lifetimeUsers = sql.prepare('SELECT COUNT(*) as count FROM users WHERE lifetime = 1').get().count;
                const activeUsers = sql.prepare('SELECT COUNT(*) as count FROM users WHERE lifetime = 1 OR (subExpiresAt IS NOT NULL AND datetime(subExpiresAt) > datetime(?))').get(now.toISOString());
                const expiredUsers = totalUsers - activeUsers;
                const totalKeys = sql.prepare('SELECT COUNT(*) as count FROM keys').get().count;
                const unusedKeys = sql.prepare('SELECT COUNT(*) as count FROM keys WHERE used = 0').get().count;
                const totalActivations = sql.prepare('SELECT COUNT(*) as count FROM activation_logs').get().count;
                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle('📈 Arcane Auth — Statystyki').setColor(0xFFD700).addFields({ name: '👥 Użytkownicy', value: `${totalUsers}`, inline: true }, { name: '🟢 Aktywni', value: `${activeUsers}`, inline: true }, { name: '🔴 Wygasłe', value: `${expiredUsers}`, inline: true }, { name: '♾️ Lifetime', value: `${lifetimeUsers}`, inline: true }, { name: '🔑 Klucze ogółem', value: `${totalKeys}`, inline: true }, { name: '⬜ Nieużyte klucze', value: `${unusedKeys}`, inline: true }, { name: '📊 Aktywacje ogółem', value: `${totalActivations}`, inline: true }).setFooter({ text: 'Arcane Auth System' }).setTimestamp()]});
            }

            // ── /launchers ──
            else if (cmd === 'launchers') {
                const launchers = sql.prepare('SELECT * FROM launchers').all();
                if (launchers.length === 0) return interaction.editReply({ content: 'ℹ️ **Brak skompilowanych launcherów w bazie.** Użyj `/addlauncher` lub uruchom launcher aby go zarejestrować.' });

                const embed = new EmbedBuilder().setTitle('🚀 Skompilowane Launchery Arcane').setColor(0x7B68EE).setFooter({ text: 'Arcane Auth System • Zdalny Self-Destruct' }).setTimestamp();
                const row = new ActionRowBuilder();
                for (const l of launchers) {
                    const statusText = l.status === 'destructed' ? '💣 **ZDESTRUOWANY**' : '🟢 **AKTYWNY**';
                    const connectedPcCount = l.downloadCount || (JSON.parse(l.activeSessions || '[]')).length || 0;
                    embed.addFields({ name: `📦 ${l.name} (\`${l.buildId}\`)`, value: `Status: ${statusText}\n💻 Pobrane / Aktywne komputery: **${connectedPcCount}**\n📅 Data: ${formatDate(l.compiledAt)}`, inline: false });
                    if (l.status !== 'destructed' && row.components.length < 5) row.addComponents(new ButtonBuilder().setCustomId(`destruct_build_${l.buildId}`).setLabel(`💣 Destruct ${l.buildId}`).setStyle(ButtonStyle.Danger));
                }
                const replyPayload = { embeds: [embed] };
                if (row.components.length > 0) replyPayload.components = [row];
                await interaction.editReply(replyPayload);
            }

            // ── /destructlauncher ──
            else if (cmd === 'destructlauncher') {
                const buildId = interaction.options.getString('buildid');
                const launcher = sql.prepare('SELECT * FROM launchers WHERE LOWER(buildId) = LOWER(?)').get(buildId);
                if (!launcher) return interaction.editReply({ content: `❌ Nie znaleziono launchera o ID \`${buildId}\`.` });
                sql.prepare('UPDATE launchers SET status = ? WHERE buildId = ?').run('destructed', buildId);
                console.log(`[LAUNCHER DESTRUCTED] Build: ${buildId} | By: ${interaction.user.tag}`);
                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle('💣 LAUNCHER ZDESTRUOWANY').setColor(0xFF0000).addFields({ name: '📦 Build ID', value: `\`${buildId}\``, inline: true }, { name: '👤 Przez', value: interaction.user.tag, inline: true }, { name: '⚠️ Wynik', value: 'Wszystkie połączone i pobrane launchery na komputerach graczy zostaną automatycznie usunięte i zdestruowane!', inline: false }).setFooter({ text: 'Arcane Remote Destruct Protocol' }).setTimestamp()]});
            }

            // ── /addlauncher ──
            else if (cmd === 'addlauncher') {
                const buildId = interaction.options.getString('buildid');
                const name = interaction.options.getString('name') || `Arcane Launcher ${buildId}`;
                let launcher = sql.prepare('SELECT * FROM launchers WHERE LOWER(buildId) = LOWER(?)').get(buildId);
                if (launcher) {
                    sql.prepare('UPDATE launchers SET name = ?, status = ? WHERE buildId = ?').run(name, 'active', buildId);
                } else {
                    sql.prepare('INSERT INTO launchers (buildId, name, compiledAt, status, downloadCount, activeSessions) VALUES (?, ?, ?, ?, ?, ?)').run(buildId, name, new Date().toISOString(), 'active', 0, '[]');
                }
                console.log(`[LAUNCHER REGISTERED] Build: ${buildId} | Name: ${name} | By: ${interaction.user.tag}`);
                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle('✅ Launcher Zarejestrowany').setColor(0x00FF7F).addFields({ name: '📦 Build ID', value: `\`${buildId}\``, inline: true }, { name: '📝 Nazwa', value: name, inline: true }, { name: '🟢 Status', value: 'AKTYWNY', inline: true }).setFooter({ text: 'Arcane Launcher Management' }).setTimestamp()]});
            }

            // ── /users ──
            else if (cmd === 'users') {
                const users = sql.prepare('SELECT * FROM users ORDER BY id ASC').all();
                const logs = sql.prepare('SELECT * FROM activation_logs').all();
                if (users.length === 0) return interaction.editReply({ content: 'ℹ️ **Brak użytkowników w bazie danych.**' });

                const embeds = [];
                let currentEmbed = new EmbedBuilder().setTitle(`👥 Pełna Lista Użytkowników Arcane (${users.length})`).setColor(0x2898FA).setFooter({ text: 'Arcane Auth System • Pełne Dane Bazy' }).setTimestamp();

                for (const u of users) {
                    if (currentEmbed.data.fields && currentEmbed.data.fields.length >= 25) { embeds.push(currentEmbed); currentEmbed = new EmbedBuilder().setTitle(`👥 Pełna Lista Użytkowników (cd.)`).setColor(0x2898FA).setFooter({ text: 'Arcane Auth System' }).setTimestamp(); }

                    const isLt = u.lifetime;
                    const expiry = u.subExpiresAt;
                    const statusText = isLt ? '♾️ LIFETIME' : (!expiry || now > new Date(expiry) ? '🔴 WYGASŁA' : `🟢 AKTYWNA (${Math.floor((new Date(expiry) - now) / (1000 * 60 * 60 * 24))} dni)`);
                    const actLog = logs.find(l => l.username && l.username.toLowerCase() === u.username.toLowerCase());
                    const ipText = actLog?.ip || 'Brak danych';
                    const hwidText = u.hwid ? `\`${u.hwid}\`` : '`Brak HWID`';

                    currentEmbed.addFields({ name: `#${u.id} 👤 ${u.username}`, value: `📊 Status: ${statusText}\n🖥️ HWID: ${hwidText}\n🌐 IP: \`${ipText}\`\n📅 Rejestracja: ${formatDate(u.registeredAt)}\n⏰ Wygaśnięcie: ${isLt ? '`♾️ LIFETIME`' : `\`${formatDate(expiry)}\``}`, inline: false });
                }
                embeds.push(currentEmbed);
                await interaction.editReply({ embeds });
            }

        } catch (err) {
            console.error(`[DISCORD BOT] Error in /${cmd}:`, err);
            await interaction.editReply({ content: '❌ Wystąpił błąd. Spróbuj ponownie.' });
        }
    });

    client.on('error', err => console.error('[DISCORD BOT] Client error:', err));
    client.login(DISCORD_BOT_TOKEN).catch(err => console.error('[DISCORD BOT] Login failed:', err));
} else {
    console.log('[DISCORD BOT] DISCORD_BOT_TOKEN not provided. Bot startup skipped.');
}

// Start Server
app.listen(PORT, () => {
    console.log(`Arcane Auth Backend Server running on port ${PORT}`);
});
