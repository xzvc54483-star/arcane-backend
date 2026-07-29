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
// Discord Bot Setup (Slash Commands ONLY - Standard Guild Intent)
// -------------------------------------------------------------------
if (DISCORD_BOT_TOKEN) {
    const client = new Client({
        intents: [
            GatewayIntentBits.Guilds
        ]
    });

    client.once('ready', async () => {
        console.log(`[DISCORD BOT] Logged in successfully as ${client.user.tag}`);

        if (DISCORD_CLIENT_ID) {
            const commands = [
                new SlashCommandBuilder()
                    .setName('generatekey')
                    .setDescription('Generate a new Arcane License Key')
                    .addIntegerOption(option =>
                        option.setName('days')
                            .setDescription('Duration in days (0 = Lifetime)')
                            .setRequired(true)
                            .setMinValue(0)
                    )
            ].map(cmd => cmd.toJSON());

            const rest = new REST({ version: '10' }).setToken(DISCORD_BOT_TOKEN);
            try {
                await rest.put(Routes.applicationCommands(DISCORD_CLIENT_ID), { body: commands });
                console.log('[DISCORD BOT] Successfully registered /generatekey slash command!');
            } catch (err) {
                console.error('[DISCORD BOT] Error registering slash commands:', err);
            }
        }
    });

    client.on('interactionCreate', async interaction => {
        if (!interaction.isChatInputCommand()) return;

        if (interaction.commandName === 'generatekey') {
            // --- Role Check ---
            const member = interaction.member;
            const hasRole = member && member.roles && member.roles.cache
                ? member.roles.cache.has(ADMIN_ROLE_ID)
                : false;

            if (!hasRole) {
                return interaction.reply({
                    content: '❌ **Brak uprawnień!** Nie masz roli wymaganej do generowania kluczy.',
                    ephemeral: true
                });
            }

            // Defer reply immediately to avoid 3s timeout
            await interaction.deferReply({ ephemeral: true });

            try {
                const days = interaction.options.getInteger('days') ?? 30;
                const isLifetime = days === 0;

                const db = loadDB();
                const newKey = generateRandomKey();

                db.keys.push({
                    code: newKey,
                    durationDays: days,
                    used: false,
                    createdAt: new Date().toISOString(),
                    createdBy: interaction.user.tag
                });

                saveDB(db);

                console.log(`[KEY CREATED via DC] Code: ${newKey} | Days: ${isLifetime ? 'LIFETIME' : days} | By: ${interaction.user.tag}`);

                const embed = new EmbedBuilder()
                    .setTitle('⚡ Arcane License Key Generated')
                    .setColor(isLifetime ? 0xFFD700 : 0x2898FA)
                    .addFields(
                        { name: '🔑 Key', value: `\`\`\`${newKey}\`\`\`` },
                        { name: '⏰ Duration', value: isLifetime ? '♾️ **LIFETIME**' : `${days} Days`, inline: true },
                        { name: '👤 Generated By', value: `<@${interaction.user.id}>`, inline: true }
                    )
                    .setFooter({ text: 'Arcane Auth System • Only you can see this' })
                    .setTimestamp();

                await interaction.editReply({ embeds: [embed] });
            } catch (err) {
                console.error('[DISCORD BOT] Error generating key:', err);
                await interaction.editReply({ content: '❌ Wystąpił błąd podczas generowania klucza. Spróbuj ponownie.' });
            }
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
