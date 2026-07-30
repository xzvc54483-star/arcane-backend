require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder, EmbedBuilder } = require('discord.js');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'db.json');

// Discord Bot Configuration (Set DISCORD_BOT_TOKEN and DISCORD_CLIENT_ID in Render environment variables)
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || "";
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "";
const ADMIN_ROLE_ID = process.env.ADMIN_ROLE_ID || "1348766448197304350";

app.use(cors());
app.use(express.json());
app.set('trust proxy', true); // Required for correct IP behind Render proxy

// Initialize JSON database if not exists
function loadDB() {
    if (!fs.existsSync(DB_FILE)) {
        const initialData = {
            keys: [
                { code: "ARCANE-TEST-KEY123", durationDays: 30, used: false }
            ],
            users: [],
            activationLogs: []
        };
        fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
        return initialData;
    }
    try {
        const raw = fs.readFileSync(DB_FILE, 'utf-8');
        return JSON.parse(raw);
    } catch (e) {
        return { keys: [], users: [], activationLogs: [] };
    }
}

function saveDB(db) {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// Generate random license key string
function generateRandomKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = 'ARCANE-';
    for (let i = 0; i < 12; i++) {
        if (i > 0 && i % 4 === 0) result += '-';
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// -------------------------------------------------------------------
// API: Generate License Key
// -------------------------------------------------------------------
app.post('/api/generatekey', (req, res) => {
    const { days } = req.body;
    const durationDays = parseInt(days) || 30;

    const db = loadDB();
    const newKey = generateRandomKey();

    db.keys.push({
        code: newKey,
        durationDays: durationDays,
        used: false,
        createdAt: new Date().toISOString()
    });

    saveDB(db);

    console.log(`[KEY CREATED] Code: ${newKey} | Days: ${durationDays}`);
    return res.json({ success: true, key: newKey, days: durationDays });
});

// -------------------------------------------------------------------
// API: Register User Account
// -------------------------------------------------------------------
app.post('/api/register', async (req, res) => {
    const { username, password, key, hwid } = req.body;
    const userIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'Unknown';

    if (!username || !password || !key) {
        return res.json({ success: false, message: "Username, password, and license key are required!" });
    }

    if (username.length < 3 || password.length < 3) {
        return res.json({ success: false, message: "Username and password must be at least 3 characters!" });
    }

    const db = loadDB();

    // Check if username already exists
    const existingUser = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (existingUser) {
        return res.json({ success: false, message: "Username is already taken!" });
    }

    // Verify key
    const keyIndex = db.keys.findIndex(k => k.code === key && !k.used);
    if (keyIndex === -1) {
        return res.json({ success: false, message: "Invalid or already used license key!" });
    }

    const targetKey = db.keys[keyIndex];

    // Mark key as used
    db.keys[keyIndex].used = true;
    db.keys[keyIndex].usedBy = username;
    db.keys[keyIndex].usedAt = new Date().toISOString();

    // Calculate subscription expiration
    const now = new Date();
    // durationDays === 0 means lifetime (never expires)
    const isLifetime = targetKey.durationDays === 0;
    const expiresAt = isLifetime ? null : new Date(now.getTime() + targetKey.durationDays * 24 * 60 * 60 * 1000);

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Add user
    const newUser = {
        id: db.users.length + 1,
        username: username,
        password: hashedPassword,
        hwid: hwid || "",
        subExpiresAt: isLifetime ? null : expiresAt.toISOString(),
        lifetime: isLifetime,
        registeredAt: now.toISOString()
    };

    db.users.push(newUser);

    // --- Activation Log ---
    if (!db.activationLogs) db.activationLogs = [];
    const logEntry = {
        event: 'LICENSE_ACTIVATED',
        username: username,
        key: key,
        ip: userIP,
        hwid: hwid || 'Not provided',
        lifetime: isLifetime,
        expiresAt: isLifetime ? 'LIFETIME' : expiresAt.toISOString(),
        activatedAt: now.toISOString()
    };
    db.activationLogs.push(logEntry);
    saveDB(db);

    console.log(`[LICENSE ACTIVATED] User: ${username} | Key: ${key} | IP: ${userIP} | HWID: ${hwid || 'N/A'} | Expires: ${isLifetime ? 'LIFETIME' : expiresAt.toISOString()}`);
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
    const db = loadDB();
    const logs = (db.activationLogs || []).slice().reverse(); // newest first
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

    const db = loadDB();
    const userIndex = db.users.findIndex(u => u.username.toLowerCase() === username.toLowerCase());

    if (userIndex === -1) {
        return res.json({ success: false, message: "User not found!" });
    }

    const user = db.users[userIndex];

    // Verify password
    const passwordValid = await bcrypt.compare(password, user.password);
    if (!passwordValid) {
        return res.json({ success: false, message: "Invalid password!" });
    }

    // Check HWID binding (if user already bound HWID)
    if (user.hwid && hwid && user.hwid !== hwid) {
        return res.json({ success: false, message: "HWID mismatch! PC not authorized." });
    }

    // Bind HWID if first login
    if (!user.hwid && hwid) {
        db.users[userIndex].hwid = hwid;
        saveDB(db);
    }

    // Check Subscription Expiration
    const now = new Date();

    // Lifetime users never expire
    if (!user.lifetime && !user.subExpiresAt) {
        return res.json({ success: false, message: "Subscription EXPIRED! Buy new license.", expired: true });
    }

    if (!user.lifetime) {
        const subDate = new Date(user.subExpiresAt);
        if (now > subDate) {
            return res.json({
                success: false,
                message: "Subscription EXPIRED! Buy new license.",
                expired: true
            });
        }

        // Calculate remaining time
        const diffMs = subDate - now;
        const daysLeft = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        const hoursLeft = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));

        console.log(`[LOGIN SUCCESS] User: ${username} | Sub Left: ${daysLeft}d ${hoursLeft}h`);
        return res.json({
            success: true,
            message: "Login successful!",
            username: user.username,
            expiresAt: user.subExpiresAt,
            lifetime: false,
            daysLeft: daysLeft,
            hoursLeft: hoursLeft
        });
    }

    console.log(`[LOGIN SUCCESS] User: ${username} | LIFETIME`);
    return res.json({
        success: true,
        message: "Login successful!",
        username: user.username,
        expiresAt: null,
        lifetime: true,
        daysLeft: -1,
        hoursLeft: -1
    });
});

// -------------------------------------------------------------------
// Discord Bot Setup — All Admin Slash Commands
// -------------------------------------------------------------------

// Helper: check admin role
function isAdmin(interaction) {
    const member = interaction.member;
    return member && member.roles && member.roles.cache
        ? member.roles.cache.has(ADMIN_ROLE_ID)
        : false;
}

// Helper: format date nicely
function formatDate(iso) {
    if (!iso) return 'N/A';
    return new Date(iso).toLocaleString('pl-PL', { timeZone: 'Europe/Warsaw' });
}

if (DISCORD_BOT_TOKEN) {
    const client = new Client({ intents: [GatewayIntentBits.Guilds] });

    client.once('ready', async () => {
        console.log(`[DISCORD BOT] Logged in as ${client.user.tag}`);

        if (DISCORD_CLIENT_ID) {
            const commands = [
                // /generatekey
                new SlashCommandBuilder()
                    .setName('generatekey')
                    .setDescription('🔑 Generuje nowy klucz licencji Arcane')
                    .addIntegerOption(o => o.setName('days').setDescription('Czas w dniach (0 = Lifetime)').setRequired(true).setMinValue(0)),

                // /userinfo
                new SlashCommandBuilder()
                    .setName('userinfo')
                    .setDescription('📋 Informacje o użytkowniku')
                    .addStringOption(o => o.setName('username').setDescription('Nazwa użytkownika').setRequired(true)),

                // /resetuser
                new SlashCommandBuilder()
                    .setName('resetuser')
                    .setDescription('🔄 Resetuje HWID użytkownika (zmiana PC)')
                    .addStringOption(o => o.setName('username').setDescription('Nazwa użytkownika').setRequired(true)),

                // /deleteuser
                new SlashCommandBuilder()
                    .setName('deleteuser')
                    .setDescription('🗑️ Usuwa użytkownika z bazy')
                    .addStringOption(o => o.setName('username').setDescription('Nazwa użytkownika').setRequired(true)),

                // /extendkey
                new SlashCommandBuilder()
                    .setName('extendkey')
                    .setDescription('⏳ Przedłuża subskrypcję użytkownika')
                    .addStringOption(o => o.setName('username').setDescription('Nazwa użytkownika').setRequired(true))
                    .addIntegerOption(o => o.setName('days').setDescription('Liczba dni do dodania').setRequired(true).setMinValue(1)),

                // /listkeys
                new SlashCommandBuilder()
                    .setName('listkeys')
                    .setDescription('📜 Lista wygenerowanych kluczy')
                    .addStringOption(o => o.setName('filter').setDescription('Filtr').addChoices(
                        { name: 'Wszystkie', value: 'all' },
                        { name: 'Nieużyte', value: 'unused' },
                        { name: 'Użyte', value: 'used' }
                    )),

                // /logs
                new SlashCommandBuilder()
                    .setName('logs')
                    .setDescription('📊 Ostatnie aktywacje licencji'),

                // /stats
                new SlashCommandBuilder()
                    .setName('stats')
                    .setDescription('📈 Statystyki systemu Arcane'),

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
        if (!interaction.isChatInputCommand()) return;

        const cmd = interaction.commandName;

        // All commands require admin role
        if (!isAdmin(interaction)) {
            return interaction.reply({ content: '❌ **Brak uprawnień!** Ta komenda jest tylko dla adminów.', ephemeral: true });
        }

        await interaction.deferReply({ ephemeral: true });

        try {
            const db = loadDB();

            // ── /generatekey ──────────────────────────────────────
            if (cmd === 'generatekey') {
                const days = interaction.options.getInteger('days') ?? 30;
                const isLifetime = days === 0;
                const newKey = generateRandomKey();

                db.keys.push({ code: newKey, durationDays: days, used: false, createdAt: new Date().toISOString(), createdBy: interaction.user.tag });
                saveDB(db);
                console.log(`[KEY CREATED] ${newKey} | ${isLifetime ? 'LIFETIME' : days + 'd'} | By: ${interaction.user.tag}`);

                await interaction.editReply({ embeds: [
                    new EmbedBuilder()
                        .setTitle('⚡ Klucz Licencji Wygenerowany')
                        .setColor(isLifetime ? 0xFFD700 : 0x2898FA)
                        .addFields(
                            { name: '🔑 Klucz', value: `\`\`\`${newKey}\`\`\`` },
                            { name: '⏰ Czas', value: isLifetime ? '♾️ LIFETIME' : `${days} dni`, inline: true },
                            { name: '👤 Przez', value: `<@${interaction.user.id}>`, inline: true }
                        )
                        .setFooter({ text: 'Arcane Auth • Tylko ty widzisz tę wiadomość' })
                        .setTimestamp()
                ]});
            }

            // ── /userinfo ──────────────────────────────────────────
            else if (cmd === 'userinfo') {
                const username = interaction.options.getString('username');
                const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());

                if (!user) {
                    return interaction.editReply({ content: `❌ Użytkownik **${username}** nie istnieje.` });
                }

                const now = new Date();
                let statusText, daysLeft;
                if (user.lifetime) {
                    statusText = '♾️ LIFETIME';
                    daysLeft = '∞';
                } else if (!user.subExpiresAt || now > new Date(user.subExpiresAt)) {
                    statusText = '🔴 WYGASŁA';
                    daysLeft = '0';
                } else {
                    const diff = new Date(user.subExpiresAt) - now;
                    daysLeft = Math.floor(diff / (1000 * 60 * 60 * 24));
                    statusText = `🟢 AKTYWNA (${daysLeft} dni)`;
                }

                // Find activation log for IP
                const activationLog = (db.activationLogs || []).find(l => l.username.toLowerCase() === username.toLowerCase());

                await interaction.editReply({ embeds: [
                    new EmbedBuilder()
                        .setTitle(`📋 Info o użytkowniku: ${user.username}`)
                        .setColor(0x2898FA)
                        .addFields(
                            { name: '🖥️ HWID', value: user.hwid || 'Nie powiązano', inline: false },
                            { name: '🌐 IP (rejestracja)', value: activationLog?.ip || 'Brak danych', inline: true },
                            { name: '📅 Rejestracja', value: formatDate(user.registeredAt), inline: true },
                            { name: '⏰ Wygaśnięcie', value: user.lifetime ? '♾️ LIFETIME' : formatDate(user.subExpiresAt), inline: true },
                            { name: '📊 Status', value: statusText, inline: true }
                        )
                        .setFooter({ text: 'Arcane Auth System' })
                        .setTimestamp()
                ]});
            }

            // ── /resetuser ─────────────────────────────────────────
            else if (cmd === 'resetuser') {
                const username = interaction.options.getString('username');
                const userIndex = db.users.findIndex(u => u.username.toLowerCase() === username.toLowerCase());

                if (userIndex === -1) {
                    return interaction.editReply({ content: `❌ Użytkownik **${username}** nie istnieje.` });
                }

                const oldHwid = db.users[userIndex].hwid || 'Brak';
                db.users[userIndex].hwid = '';
                saveDB(db);
                console.log(`[HWID RESET] User: ${username} | Old HWID: ${oldHwid} | By: ${interaction.user.tag}`);

                await interaction.editReply({ embeds: [
                    new EmbedBuilder()
                        .setTitle('🔄 HWID Zresetowany')
                        .setColor(0xFFA500)
                        .addFields(
                            { name: '👤 Użytkownik', value: username, inline: true },
                            { name: '🖥️ Stary HWID', value: oldHwid, inline: true },
                            { name: '✅ Status', value: 'Użytkownik może zalogować się z nowego PC', inline: false }
                        )
                        .setFooter({ text: `Reset przez ${interaction.user.tag}` })
                        .setTimestamp()
                ]});
            }

            // ── /deleteuser ────────────────────────────────────────
            else if (cmd === 'deleteuser') {
                const username = interaction.options.getString('username');
                const userIndex = db.users.findIndex(u => u.username.toLowerCase() === username.toLowerCase());

                if (userIndex === -1) {
                    return interaction.editReply({ content: `❌ Użytkownik **${username}** nie istnieje.` });
                }

                db.users.splice(userIndex, 1);
                saveDB(db);
                console.log(`[USER DELETED] User: ${username} | By: ${interaction.user.tag}`);

                await interaction.editReply({ embeds: [
                    new EmbedBuilder()
                        .setTitle('🗑️ Użytkownik Usunięty')
                        .setColor(0xFF4444)
                        .addFields(
                            { name: '👤 Usunięty użytkownik', value: username, inline: true },
                            { name: '👮 Przez', value: interaction.user.tag, inline: true }
                        )
                        .setFooter({ text: 'Arcane Auth System' })
                        .setTimestamp()
                ]});
            }

            // ── /extendkey ─────────────────────────────────────────
            else if (cmd === 'extendkey') {
                const username = interaction.options.getString('username');
                const days = interaction.options.getInteger('days');
                const userIndex = db.users.findIndex(u => u.username.toLowerCase() === username.toLowerCase());

                if (userIndex === -1) {
                    return interaction.editReply({ content: `❌ Użytkownik **${username}** nie istnieje.` });
                }

                const user = db.users[userIndex];
                if (user.lifetime) {
                    return interaction.editReply({ content: `ℹ️ Użytkownik **${username}** ma już LIFETIME — nie można przedłużyć.` });
                }

                const now = new Date();
                const currentExpiry = user.subExpiresAt ? new Date(user.subExpiresAt) : now;
                const base = currentExpiry > now ? currentExpiry : now;
                const newExpiry = new Date(base.getTime() + days * 24 * 60 * 60 * 1000);

                db.users[userIndex].subExpiresAt = newExpiry.toISOString();
                saveDB(db);
                console.log(`[SUB EXTENDED] User: ${username} | +${days} days | New expiry: ${newExpiry.toISOString()} | By: ${interaction.user.tag}`);

                await interaction.editReply({ embeds: [
                    new EmbedBuilder()
                        .setTitle('⏳ Subskrypcja Przedłużona')
                        .setColor(0x00CC66)
                        .addFields(
                            { name: '👤 Użytkownik', value: username, inline: true },
                            { name: '➕ Dodano dni', value: `${days} dni`, inline: true },
                            { name: '📅 Nowe wygaśnięcie', value: formatDate(newExpiry.toISOString()), inline: false }
                        )
                        .setFooter({ text: `Przedłużono przez ${interaction.user.tag}` })
                        .setTimestamp()
                ]});
            }

            // ── /listkeys ──────────────────────────────────────────
            else if (cmd === 'listkeys') {
                const filter = interaction.options.getString('filter') || 'all';
                let keys = db.keys;
                if (filter === 'unused') keys = keys.filter(k => !k.used);
                if (filter === 'used') keys = keys.filter(k => k.used);

                const latest = keys.slice(-15).reverse(); // last 15, newest first
                const lines = latest.map(k => {
                    const status = k.used ? `✅ ${k.usedBy}` : '⬜ Nieużyty';
                    const duration = k.durationDays === 0 ? '♾️ LT' : `${k.durationDays}d`;
                    return `\`${k.code}\` • ${duration} • ${status}`;
                });

                await interaction.editReply({ embeds: [
                    new EmbedBuilder()
                        .setTitle(`📜 Klucze licencji (${filter}) — ${keys.length} szt.`)
                        .setColor(0x7B68EE)
                        .setDescription(lines.length > 0 ? lines.join('\n') : 'Brak kluczy.')
                        .setFooter({ text: `Pokazuję max 15 najnowszych | Łącznie: ${db.keys.length}` })
                        .setTimestamp()
                ]});
            }

            // ── /logs ──────────────────────────────────────────────
            else if (cmd === 'logs') {
                const logs = (db.activationLogs || []).slice(-10).reverse();
                const lines = logs.map((l, i) =>
                    `**${i+1}.** \`${l.username}\` • \`${l.ip}\` • HWID: \`${l.hwid?.substring(0,12) || 'N/A'}...\` • ${formatDate(l.activatedAt)}`
                );

                await interaction.editReply({ embeds: [
                    new EmbedBuilder()
                        .setTitle('📊 Ostatnie aktywacje licencji')
                        .setColor(0x2898FA)
                        .setDescription(lines.length > 0 ? lines.join('\n') : 'Brak logów.')
                        .setFooter({ text: `Łącznie aktywacji: ${(db.activationLogs || []).length}` })
                        .setTimestamp()
                ]});
            }

            // ── /stats ─────────────────────────────────────────────
            else if (cmd === 'stats') {
                const now = new Date();
                const totalUsers = db.users.length;
                const lifetimeUsers = db.users.filter(u => u.lifetime).length;
                const activeUsers = db.users.filter(u => u.lifetime || (u.subExpiresAt && new Date(u.subExpiresAt) > now)).length;
                const expiredUsers = totalUsers - activeUsers;
                const totalKeys = db.keys.length;
                const unusedKeys = db.keys.filter(k => !k.used).length;
                const totalActivations = (db.activationLogs || []).length;

                await interaction.editReply({ embeds: [
                    new EmbedBuilder()
                        .setTitle('📈 Arcane Auth — Statystyki')
                        .setColor(0xFFD700)
                        .addFields(
                            { name: '👥 Użytkownicy', value: `${totalUsers}`, inline: true },
                            { name: '🟢 Aktywni', value: `${activeUsers}`, inline: true },
                            { name: '🔴 Wygasłe', value: `${expiredUsers}`, inline: true },
                            { name: '♾️ Lifetime', value: `${lifetimeUsers}`, inline: true },
                            { name: '🔑 Klucze ogółem', value: `${totalKeys}`, inline: true },
                            { name: '⬜ Nieużyte klucze', value: `${unusedKeys}`, inline: true },
                            { name: '📊 Aktywacje ogółem', value: `${totalActivations}`, inline: true }
                        )
                        .setFooter({ text: 'Arcane Auth System' })
                        .setTimestamp()
                ]});
            }

        } catch (err) {
            console.error(`[DISCORD BOT] Error in /${cmd}:`, err);
            await interaction.editReply({ content: '❌ Wystąpił błąd. Spróbuj ponownie.' });
        }
    });

    client.login(DISCORD_BOT_TOKEN).catch(err => console.error('[DISCORD BOT] Login failed:', err));
} else {
    console.log('[DISCORD BOT] DISCORD_BOT_TOKEN not provided. Bot startup skipped.');
}

// Start Server
app.listen(PORT, () => {
    console.log(`Arcane Auth Backend Server running on port ${PORT}`);
});
