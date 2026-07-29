import { Elysia } from 'elysia';
import { cors } from '@elysiajs/cors';
import postgres from 'postgres';
import { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder, EmbedBuilder } from 'discord.js';

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL || "";
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || "";
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "";
const ADMIN_ROLE_ID = process.env.ADMIN_ROLE_ID || "1348766448197304350";

// Initialize external PostgreSQL client
const sql = DATABASE_URL ? postgres(DATABASE_URL, { ssl: DATABASE_URL.includes('dpg-') ? false : 'require' }) : null;

// Rate-limiting / Brute-force protection memory store
interface FailedAttempt {
    count: number;
    blockedUntil: number;
}
const loginAttempts = new Map<string, FailedAttempt>();

// Anti Brute-Force Rate Limiter
function checkRateLimit(identifier: string): { allowed: boolean; remainingSec: number } {
    const now = Date.now();
    const attempt = loginAttempts.get(identifier);

    if (attempt) {
        if (attempt.blockedUntil > now) {
            const remainingSec = Math.ceil((attempt.blockedUntil - now) / 1000);
            return { allowed: false, remainingSec };
        }
        if (attempt.blockedUntil <= now && attempt.count >= 5) {
            loginAttempts.delete(identifier);
        }
    }
    return { allowed: true, remainingSec: 0 };
}

function recordFailedAttempt(identifier: string) {
    const now = Date.now();
    const attempt = loginAttempts.get(identifier) || { count: 0, blockedUntil: 0 };
    attempt.count += 1;
    if (attempt.count >= 5) {
        attempt.blockedUntil = now + (15 * 60 * 1000);
        console.warn(`[SECURITY ALERT] Brute-force detected! Blocked '${identifier}' for 15 minutes.`);
    }
    loginAttempts.set(identifier, attempt);
}

function resetFailedAttempt(identifier: string) {
    loginAttempts.delete(identifier);
}

// Helper: Generate secure random key
function generateRandomKey(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = 'ARCANE-';
    for (let i = 0; i < 12; i++) {
        if (i > 0 && i % 4 === 0) result += '-';
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// Helper: format date nicely (Warsaw timezone)
function formatDate(date: Date | string | null): string {
    if (!date) return 'N/A';
    return new Date(date).toLocaleString('pl-PL', { timeZone: 'Europe/Warsaw' });
}

// Helper: check admin role in Discord interaction
function isAdmin(interaction: any): boolean {
    const member = interaction.member;
    return member && member.roles && member.roles.cache
        ? member.roles.cache.has(ADMIN_ROLE_ID)
        : false;
}

// Initialize Database Tables (with new columns for lifetime & activation_logs)
async function initDatabase() {
    if (!sql) {
        console.log('[DATABASE] Warning: DATABASE_URL not set.');
        return;
    }

    try {
        // Keys table
        await sql`
            CREATE TABLE IF NOT EXISTS keys (
                id SERIAL PRIMARY KEY,
                code VARCHAR(64) UNIQUE NOT NULL,
                duration_days INT NOT NULL DEFAULT 30,
                used BOOLEAN DEFAULT FALSE,
                used_by VARCHAR(64),
                used_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by VARCHAR(64)
            );
        `;

        // Users table — sub_expires_at nullable (lifetime users have NULL)
        await sql`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(64) UNIQUE NOT NULL,
                password TEXT NOT NULL,
                hwid VARCHAR(128),
                sub_expires_at TIMESTAMP,
                lifetime BOOLEAN DEFAULT FALSE,
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `;

        // Activation logs table
        await sql`
            CREATE TABLE IF NOT EXISTS activation_logs (
                id SERIAL PRIMARY KEY,
                username VARCHAR(64),
                key_code VARCHAR(64),
                ip VARCHAR(64),
                hwid VARCHAR(128),
                lifetime BOOLEAN DEFAULT FALSE,
                expires_at VARCHAR(64),
                activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `;

        // Safely add missing columns to existing tables (idempotent)
        await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS lifetime BOOLEAN DEFAULT FALSE;`;
        await sql`ALTER TABLE users ALTER COLUMN sub_expires_at DROP NOT NULL;`;

        console.log('[DATABASE] PostgreSQL tables verified & ready.');
    } catch (err) {
        console.error('[DATABASE ERROR] Failed to initialize PostgreSQL:', err);
    }
}

initDatabase();

// -------------------------------------------------------------------
// ElysiaJS App
// -------------------------------------------------------------------
const app = new Elysia()
    .use(cors())

    // Security Headers
    .onRequest(({ set }) => {
        set.headers['X-Content-Type-Options'] = 'nosniff';
        set.headers['X-Frame-Options'] = 'DENY';
        set.headers['X-XSS-Protection'] = '1; mode=block';
    })

    .get('/', () => ({
        status: 'online',
        server: 'ElysiaJS + Bun (Secure API)',
        database: sql ? 'External PostgreSQL (Protected)' : 'Disconnected'
    }))

    // -------------------------------------------------------------------
    // API: Generate License Key
    // -------------------------------------------------------------------
    .post('/api/generatekey', async ({ body }: { body: { days?: number } }) => {
        if (!sql) return { success: false, message: "Database connection unavailable." };

        const durationDays = parseInt(String(body?.days ?? 30));
        const isLifetime = durationDays === 0;
        const newKey = generateRandomKey();

        await sql`
            INSERT INTO keys (code, duration_days, used)
            VALUES (${newKey}, ${durationDays}, FALSE);
        `;

        console.log(`[KEY-GEN] Code: ${newKey} | Days: ${isLifetime ? 'LIFETIME' : durationDays}`);
        return { success: true, key: newKey, days: durationDays, lifetime: isLifetime };
    })

    // -------------------------------------------------------------------
    // API: Register User Account
    // -------------------------------------------------------------------
    .post('/api/register', async ({ body, request }: { body: { username?: string; password?: string; key?: string; hwid?: string }; request: Request }) => {
        const username = body?.username?.trim();
        const password = body?.password;
        const key = body?.key?.trim();
        const hwid = body?.hwid?.trim();

        if (!username || !password || !key) {
            return { success: false, message: "Username, password, and license key are required!" };
        }

        if (username.length < 3 || username.length > 32 || password.length < 3 || password.length > 128) {
            return { success: false, message: "Invalid username or password length!" };
        }

        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            return { success: false, message: "Username contains invalid characters!" };
        }

        if (!sql) return { success: false, message: "Database connection unavailable." };

        const clientIP = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'Unknown';
        const rateCheck = checkRateLimit(clientIP);
        if (!rateCheck.allowed) {
            return { success: false, message: `Too many attempts! Blocked for ${rateCheck.remainingSec} seconds.` };
        }

        const existingUser = await sql`SELECT id FROM users WHERE LOWER(username) = LOWER(${username})`;
        if (existingUser.length > 0) {
            return { success: false, message: "Username is already taken!" };
        }

        const keysFound = await sql`SELECT * FROM keys WHERE code = ${key} AND used = FALSE`;
        if (keysFound.length === 0) {
            recordFailedAttempt(clientIP);
            return { success: false, message: "Invalid or already used license key!" };
        }

        const targetKey = keysFound[0];
        const isLifetime = targetKey.duration_days === 0;

        await sql`UPDATE keys SET used = TRUE, used_by = ${username}, used_at = NOW() WHERE code = ${key};`;

        const now = new Date();
        const expiresAt = isLifetime ? null : new Date(now.getTime() + targetKey.duration_days * 24 * 60 * 60 * 1000);

        const hashedPassword = await Bun.password.hash(password, {
            algorithm: 'argon2id',
            memoryCost: 65536,
            timeCost: 3
        });

        await sql`
            INSERT INTO users (username, password, hwid, sub_expires_at, lifetime)
            VALUES (${username}, ${hashedPassword}, ${hwid || ''}, ${expiresAt}, ${isLifetime});
        `;

        // Save activation log
        await sql`
            INSERT INTO activation_logs (username, key_code, ip, hwid, lifetime, expires_at)
            VALUES (${username}, ${key}, ${clientIP}, ${hwid || 'Not provided'}, ${isLifetime}, ${isLifetime ? 'LIFETIME' : expiresAt!.toISOString()});
        `;

        resetFailedAttempt(clientIP);
        console.log(`[REGISTER-SUCCESS] User: ${username} | IP: ${clientIP} | HWID: ${hwid} | Expires: ${isLifetime ? 'LIFETIME' : expiresAt!.toISOString()}`);

        return {
            success: true,
            message: "Account registered successfully!",
            expiresAt: isLifetime ? null : expiresAt!.toISOString(),
            lifetime: isLifetime
        };
    })

    // -------------------------------------------------------------------
    // API: Login User
    // -------------------------------------------------------------------
    .post('/api/login', async ({ body, request }: { body: { username?: string; password?: string; hwid?: string }; request: Request }) => {
        const username = body?.username?.trim();
        const password = body?.password;
        const hwid = body?.hwid?.trim();

        if (!username || !password) {
            return { success: false, message: "Username and password are required!" };
        }

        if (!sql) return { success: false, message: "Database connection unavailable." };

        const clientIP = request.headers.get('x-forwarded-for') || 'local';
        const rateCheckUser = checkRateLimit(username.toLowerCase());
        const rateCheckIP = checkRateLimit(clientIP);

        if (!rateCheckUser.allowed || !rateCheckIP.allowed) {
            const waitTime = Math.max(rateCheckUser.remainingSec, rateCheckIP.remainingSec);
            return { success: false, message: `Account locked due to multiple failed logins! Try again in ${waitTime} seconds.` };
        }

        const usersFound = await sql`SELECT * FROM users WHERE LOWER(username) = LOWER(${username})`;
        if (usersFound.length === 0) {
            recordFailedAttempt(username.toLowerCase());
            recordFailedAttempt(clientIP);
            return { success: false, message: "Invalid username or password!" };
        }

        const user = usersFound[0];

        const passwordValid = await Bun.password.verify(password, user.password);
        if (!passwordValid) {
            recordFailedAttempt(username.toLowerCase());
            recordFailedAttempt(clientIP);
            return { success: false, message: "Invalid username or password!" };
        }

        if (user.hwid && hwid && user.hwid !== hwid) {
            recordFailedAttempt(username.toLowerCase());
            console.warn(`[HWID MISMATCH] User '${username}' from unauthorized HWID: ${hwid}`);
            return { success: false, message: "HWID mismatch! This PC is not authorized for this account." };
        }

        if (!user.hwid && hwid) {
            await sql`UPDATE users SET hwid = ${hwid} WHERE id = ${user.id}`;
        }

        // Lifetime users never expire
        if (user.lifetime) {
            resetFailedAttempt(username.toLowerCase());
            resetFailedAttempt(clientIP);
            console.log(`[LOGIN-SUCCESS] User: ${username} | LIFETIME`);
            return {
                success: true,
                message: "Login successful!",
                username: user.username,
                expiresAt: null,
                lifetime: true,
                daysLeft: -1,
                hoursLeft: -1
            };
        }

        const now = new Date();
        const subDate = new Date(user.sub_expires_at);

        if (now > subDate) {
            return { success: false, message: "Subscription EXPIRED! Buy new license.", expired: true };
        }

        resetFailedAttempt(username.toLowerCase());
        resetFailedAttempt(clientIP);

        const diffMs = subDate.getTime() - now.getTime();
        const daysLeft = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        const hoursLeft = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));

        console.log(`[LOGIN-SUCCESS] User: ${username} | Sub Left: ${daysLeft}d ${hoursLeft}h`);
        return {
            success: true,
            message: "Login successful!",
            username: user.username,
            expiresAt: user.sub_expires_at,
            lifetime: false,
            daysLeft,
            hoursLeft
        };
    })

    // -------------------------------------------------------------------
    // API: View Activation Logs
    // -------------------------------------------------------------------
    .get('/api/logs', async () => {
        if (!sql) return { success: false, message: "Database connection unavailable." };
        const logs = await sql`SELECT * FROM activation_logs ORDER BY activated_at DESC LIMIT 100`;
        return { success: true, total: logs.length, logs };
    })

    .listen(PORT);

console.log(`🚀 ElysiaJS + Bun Secure Auth Backend running on port ${PORT}`);

// -------------------------------------------------------------------
// Discord Bot — All Admin Slash Commands
// -------------------------------------------------------------------
if (DISCORD_BOT_TOKEN) {
    const client = new Client({ intents: [GatewayIntentBits.Guilds] });

    client.once('ready', async () => {
        console.log(`[DISCORD BOT] Logged in as ${client.user?.tag}`);

        if (DISCORD_CLIENT_ID) {
            const commands = [
                new SlashCommandBuilder()
                    .setName('generatekey')
                    .setDescription('🔑 Generuje nowy klucz licencji Arcane')
                    .addIntegerOption(o => o.setName('days').setDescription('Czas w dniach (0 = Lifetime)').setRequired(true).setMinValue(0)),

                new SlashCommandBuilder()
                    .setName('userinfo')
                    .setDescription('📋 Informacje o użytkowniku')
                    .addStringOption(o => o.setName('username').setDescription('Nazwa użytkownika').setRequired(true)),

                new SlashCommandBuilder()
                    .setName('resetuser')
                    .setDescription('🔄 Resetuje HWID użytkownika (zmiana PC)')
                    .addStringOption(o => o.setName('username').setDescription('Nazwa użytkownika').setRequired(true)),

                new SlashCommandBuilder()
                    .setName('deleteuser')
                    .setDescription('🗑️ Usuwa użytkownika z bazy')
                    .addStringOption(o => o.setName('username').setDescription('Nazwa użytkownika').setRequired(true)),

                new SlashCommandBuilder()
                    .setName('extendkey')
                    .setDescription('⏳ Przedłuża subskrypcję użytkownika')
                    .addStringOption(o => o.setName('username').setDescription('Nazwa użytkownika').setRequired(true))
                    .addIntegerOption(o => o.setName('days').setDescription('Liczba dni do dodania').setRequired(true).setMinValue(1)),

                new SlashCommandBuilder()
                    .setName('listkeys')
                    .setDescription('📜 Lista wygenerowanych kluczy')
                    .addStringOption(o => o.setName('filter').setDescription('Filtr').addChoices(
                        { name: 'Wszystkie', value: 'all' },
                        { name: 'Nieużyte', value: 'unused' },
                        { name: 'Użyte', value: 'used' }
                    )),

                new SlashCommandBuilder()
                    .setName('logs')
                    .setDescription('📊 Ostatnie aktywacje licencji'),

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

    client.on('interactionCreate', async (interaction: any) => {
        if (!interaction.isChatInputCommand()) return;

        const cmd = interaction.commandName;

        if (!isAdmin(interaction)) {
            return interaction.reply({ content: '❌ **Brak uprawnień!** Ta komenda jest tylko dla adminów.', ephemeral: true });
        }

        await interaction.deferReply({ ephemeral: true });

        try {
            // ── /generatekey ──────────────────────────────────────────
            if (cmd === 'generatekey') {
                const days = interaction.options.getInteger('days') ?? 30;
                const isLifetime = days === 0;
                const newKey = generateRandomKey();

                if (sql) {
                    await sql`INSERT INTO keys (code, duration_days, used, created_by) VALUES (${newKey}, ${days}, FALSE, ${interaction.user.tag});`;
                }

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

            // ── /userinfo ─────────────────────────────────────────────
            else if (cmd === 'userinfo') {
                if (!sql) return interaction.editReply({ content: '❌ Brak połączenia z bazą.' });
                const username = interaction.options.getString('username');
                const users = await sql`SELECT * FROM users WHERE LOWER(username) = LOWER(${username})`;

                if (users.length === 0) {
                    return interaction.editReply({ content: `❌ Użytkownik **${username}** nie istnieje.` });
                }

                const user = users[0];
                const now = new Date();
                let statusText: string;

                if (user.lifetime) {
                    statusText = '♾️ LIFETIME';
                } else if (!user.sub_expires_at || now > new Date(user.sub_expires_at)) {
                    statusText = '🔴 WYGASŁA';
                } else {
                    const diff = new Date(user.sub_expires_at).getTime() - now.getTime();
                    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
                    statusText = `🟢 AKTYWNA (${days} dni)`;
                }

                const logs = await sql`SELECT * FROM activation_logs WHERE LOWER(username) = LOWER(${username}) LIMIT 1`;
                const activationLog = logs[0];

                await interaction.editReply({ embeds: [
                    new EmbedBuilder()
                        .setTitle(`📋 Info o użytkowniku: ${user.username}`)
                        .setColor(0x2898FA)
                        .addFields(
                            { name: '🖥️ HWID', value: user.hwid || 'Nie powiązano', inline: false },
                            { name: '🌐 IP (rejestracja)', value: activationLog?.ip || 'Brak danych', inline: true },
                            { name: '📅 Rejestracja', value: formatDate(user.registered_at), inline: true },
                            { name: '⏰ Wygaśnięcie', value: user.lifetime ? '♾️ LIFETIME' : formatDate(user.sub_expires_at), inline: true },
                            { name: '📊 Status', value: statusText, inline: true }
                        )
                        .setFooter({ text: 'Arcane Auth System' })
                        .setTimestamp()
                ]});
            }

            // ── /resetuser ────────────────────────────────────────────
            else if (cmd === 'resetuser') {
                if (!sql) return interaction.editReply({ content: '❌ Brak połączenia z bazą.' });
                const username = interaction.options.getString('username');
                const users = await sql`SELECT * FROM users WHERE LOWER(username) = LOWER(${username})`;

                if (users.length === 0) {
                    return interaction.editReply({ content: `❌ Użytkownik **${username}** nie istnieje.` });
                }

                const oldHwid = users[0].hwid || 'Brak';
                await sql`UPDATE users SET hwid = '' WHERE LOWER(username) = LOWER(${username})`;
                console.log(`[HWID RESET] User: ${username} | By: ${interaction.user.tag}`);

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

            // ── /deleteuser ───────────────────────────────────────────
            else if (cmd === 'deleteuser') {
                if (!sql) return interaction.editReply({ content: '❌ Brak połączenia z bazą.' });
                const username = interaction.options.getString('username');
                const users = await sql`SELECT id FROM users WHERE LOWER(username) = LOWER(${username})`;

                if (users.length === 0) {
                    return interaction.editReply({ content: `❌ Użytkownik **${username}** nie istnieje.` });
                }

                await sql`DELETE FROM users WHERE LOWER(username) = LOWER(${username})`;
                console.log(`[USER DELETED] ${username} | By: ${interaction.user.tag}`);

                await interaction.editReply({ embeds: [
                    new EmbedBuilder()
                        .setTitle('🗑️ Użytkownik Usunięty')
                        .setColor(0xFF4444)
                        .addFields(
                            { name: '👤 Usunięty', value: username, inline: true },
                            { name: '👮 Przez', value: interaction.user.tag, inline: true }
                        )
                        .setFooter({ text: 'Arcane Auth System' })
                        .setTimestamp()
                ]});
            }

            // ── /extendkey ────────────────────────────────────────────
            else if (cmd === 'extendkey') {
                if (!sql) return interaction.editReply({ content: '❌ Brak połączenia z bazą.' });
                const username = interaction.options.getString('username');
                const days = interaction.options.getInteger('days');
                const users = await sql`SELECT * FROM users WHERE LOWER(username) = LOWER(${username})`;

                if (users.length === 0) {
                    return interaction.editReply({ content: `❌ Użytkownik **${username}** nie istnieje.` });
                }

                const user = users[0];
                if (user.lifetime) {
                    return interaction.editReply({ content: `ℹ️ Użytkownik **${username}** ma LIFETIME — nie można przedłużyć.` });
                }

                const now = new Date();
                const currentExpiry = user.sub_expires_at ? new Date(user.sub_expires_at) : now;
                const base = currentExpiry > now ? currentExpiry : now;
                const newExpiry = new Date(base.getTime() + days * 24 * 60 * 60 * 1000);

                await sql`UPDATE users SET sub_expires_at = ${newExpiry} WHERE LOWER(username) = LOWER(${username})`;
                console.log(`[SUB EXTENDED] ${username} | +${days}d | New: ${newExpiry.toISOString()} | By: ${interaction.user.tag}`);

                await interaction.editReply({ embeds: [
                    new EmbedBuilder()
                        .setTitle('⏳ Subskrypcja Przedłużona')
                        .setColor(0x00CC66)
                        .addFields(
                            { name: '👤 Użytkownik', value: username, inline: true },
                            { name: '➕ Dodano dni', value: `${days} dni`, inline: true },
                            { name: '📅 Nowe wygaśnięcie', value: formatDate(newExpiry), inline: false }
                        )
                        .setFooter({ text: `Przedłużono przez ${interaction.user.tag}` })
                        .setTimestamp()
                ]});
            }

            // ── /listkeys ─────────────────────────────────────────────
            else if (cmd === 'listkeys') {
                if (!sql) return interaction.editReply({ content: '❌ Brak połączenia z bazą.' });
                const filter = interaction.options.getString('filter') || 'all';

                let keys;
                if (filter === 'unused') keys = await sql`SELECT * FROM keys WHERE used = FALSE ORDER BY created_at DESC LIMIT 15`;
                else if (filter === 'used') keys = await sql`SELECT * FROM keys WHERE used = TRUE ORDER BY created_at DESC LIMIT 15`;
                else keys = await sql`SELECT * FROM keys ORDER BY created_at DESC LIMIT 15`;

                const totalResult = await sql`SELECT COUNT(*) as count FROM keys`;
                const total = totalResult[0].count;

                const lines = keys.map((k: any) => {
                    const status = k.used ? `✅ ${k.used_by}` : '⬜ Nieużyty';
                    const duration = k.duration_days === 0 ? '♾️ LT' : `${k.duration_days}d`;
                    return `\`${k.code}\` • ${duration} • ${status}`;
                });

                await interaction.editReply({ embeds: [
                    new EmbedBuilder()
                        .setTitle(`📜 Klucze licencji (${filter})`)
                        .setColor(0x7B68EE)
                        .setDescription(lines.length > 0 ? lines.join('\n') : 'Brak kluczy.')
                        .setFooter({ text: `Pokazuję max 15 najnowszych | Łącznie: ${total}` })
                        .setTimestamp()
                ]});
            }

            // ── /logs ─────────────────────────────────────────────────
            else if (cmd === 'logs') {
                if (!sql) return interaction.editReply({ content: '❌ Brak połączenia z bazą.' });
                const logs = await sql`SELECT * FROM activation_logs ORDER BY activated_at DESC LIMIT 10`;
                const totalResult = await sql`SELECT COUNT(*) as count FROM activation_logs`;
                const total = totalResult[0].count;

                const lines = logs.map((l: any, i: number) =>
                    `**${i+1}.** \`${l.username}\` • \`${l.ip}\` • HWID: \`${(l.hwid || 'N/A').substring(0,12)}...\` • ${formatDate(l.activated_at)}`
                );

                await interaction.editReply({ embeds: [
                    new EmbedBuilder()
                        .setTitle('📊 Ostatnie aktywacje licencji')
                        .setColor(0x2898FA)
                        .setDescription(lines.length > 0 ? lines.join('\n') : 'Brak logów.')
                        .setFooter({ text: `Łącznie aktywacji: ${total}` })
                        .setTimestamp()
                ]});
            }

            // ── /stats ────────────────────────────────────────────────
            else if (cmd === 'stats') {
                if (!sql) return interaction.editReply({ content: '❌ Brak połączenia z bazą.' });

                const totalUsers = (await sql`SELECT COUNT(*) as count FROM users`)[0].count;
                const lifetimeUsers = (await sql`SELECT COUNT(*) as count FROM users WHERE lifetime = TRUE`)[0].count;
                const activeUsers = (await sql`SELECT COUNT(*) as count FROM users WHERE lifetime = TRUE OR sub_expires_at > NOW()`)[0].count;
                const expiredUsers = (await sql`SELECT COUNT(*) as count FROM users WHERE lifetime = FALSE AND (sub_expires_at IS NULL OR sub_expires_at <= NOW())`)[0].count;
                const totalKeys = (await sql`SELECT COUNT(*) as count FROM keys`)[0].count;
                const unusedKeys = (await sql`SELECT COUNT(*) as count FROM keys WHERE used = FALSE`)[0].count;
                const totalActivations = (await sql`SELECT COUNT(*) as count FROM activation_logs`)[0].count;

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

    client.login(DISCORD_BOT_TOKEN).catch((err: any) => console.error('[DISCORD BOT] Login failed:', err));
}
