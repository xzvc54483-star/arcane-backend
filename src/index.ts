import { Elysia } from 'elysia';
import { cors } from '@elysiajs/cors';
import Database from 'better-sqlite3';
import { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, MessageFlags, PermissionFlagsBits } from 'discord.js';
import path from 'path';
import fs from 'fs';
import bcrypt from 'bcryptjs';

const PORT = Number(process.env.PORT) || 3000;
const DB_FILE = path.join(process.cwd(), 'arcane.db');
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || "";
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "";
const ADMIN_ROLE_ID = process.env.ADMIN_ROLE_ID || "1348766448197304350";

// Initialize SQLite database
const sql = new Database(DB_FILE);
sql.pragma('journal_mode = WAL');
sql.pragma('foreign_keys = ON');

// Initialize SQLite Tables
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
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                hwid TEXT DEFAULT '',
                subExpiresAt TEXT,
                lifetime INTEGER DEFAULT 0,
                registeredAt TEXT NOT NULL
            );
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
            );
            CREATE TABLE IF NOT EXISTS launchers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                buildId TEXT UNIQUE NOT NULL,
                name TEXT,
                compiledAt TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                downloadCount INTEGER DEFAULT 0,
                activeSessions TEXT DEFAULT '[]'
            );
        `);
        console.log('[DB] SQLite tables initialized successfully.');
    } catch (err: any) {
        console.error('[DB ERROR] Failed to initialize SQLite tables:', err?.message || err);
    }
}

initDatabase();

// Helpers
function generateRandomKey(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = 'ARCANE-';
    for (let i = 0; i < 12; i++) {
        if (i > 0 && i % 4 === 0) result += '-';
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

function formatDate(date: Date | string | null): string {
    if (!date) return 'N/A';
    return new Date(date).toLocaleString('pl-PL', { timeZone: 'Europe/Warsaw' });
}

function isAdmin(interaction: any): boolean {
    if (interaction.guild && interaction.guild.ownerId === interaction.user.id) {
        return true;
    }
    if (interaction.memberPermissions && interaction.memberPermissions.has(PermissionFlagsBits.Administrator)) {
        return true;
    }
    const member = interaction.member;
    if (member) {
        if (member.permissions && typeof member.permissions.has === 'function' && member.permissions.has(PermissionFlagsBits.Administrator)) {
            return true;
        }
        if (member.roles) {
            if (member.roles.cache && typeof member.roles.cache.has === 'function' && member.roles.cache.has(ADMIN_ROLE_ID)) {
                return true;
            }
            if (Array.isArray(member.roles) && member.roles.includes(ADMIN_ROLE_ID)) {
                return true;
            }
        }
    }
    return false;
}

// -------------------------------------------------------------------
// Discord Bot Setup
// -------------------------------------------------------------------
if (DISCORD_BOT_TOKEN) {
    const client = new Client({ intents: [GatewayIntentBits.Guilds] });

    client.once('clientReady', async () => {
        console.log(`[DISCORD BOT] Logged in as ${client.user?.tag}`);

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
                new SlashCommandBuilder().setName('help').setDescription('ℹ️ Wyświetla listę wszystkich dostępnych komend bota Arcane'),
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
        if (interaction.isButton()) {
            if (!isAdmin(interaction)) {
                return interaction.reply({ content: '❌ **Brak uprawnień!** Ta komenda jest tylko dla adminów.', flags: MessageFlags.Ephemeral });
            }
            if (interaction.customId.startsWith('destruct_build_')) {
                await interaction.deferUpdate().catch(() => {});
                const targetBuildId = interaction.customId.replace('destruct_build_', '');
                const launcher = sql.prepare('SELECT * FROM launchers WHERE LOWER(buildId) = LOWER(?)').get(targetBuildId) as any;
                if (launcher) {
                    sql.prepare('UPDATE launchers SET status = ? WHERE buildId = ?').run('destructed', targetBuildId);
                    console.log(`[LAUNCHER DESTRUCTED] Build: ${targetBuildId} | By: ${interaction.user.tag}`);
                    await interaction.followUp({ content: `💣 **SYGNAŁ DESTRUCT WYSŁANY!**\nLauncher o Build ID \`${targetBuildId}\` został zdestruowany. Wszystkie pobrane instancje u użytkowników ulegną samozniszczeniu przy następnym połączeniu.`, flags: MessageFlags.Ephemeral }).catch(() => {});
                } else {
                    await interaction.followUp({ content: `❌ Nie znaleziono launchera o ID \`${targetBuildId}\`.`, flags: MessageFlags.Ephemeral }).catch(() => {});
                }
            }
            return;
        }

        if (!interaction.isChatInputCommand()) return;

        const cmd = interaction.commandName;

        if (!isAdmin(interaction)) {
            return interaction.reply({ content: '❌ **Brak uprawnień!** Ta komenda jest tylko dla adminów.', flags: MessageFlags.Ephemeral });
        }

        try {
            if (!interaction.deferred && !interaction.replied) {
                await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            }
        } catch (e: any) {
            console.error('[DISCORD BOT] deferReply skipped/error:', e?.message || e);
        }

        try {
            const now = new Date();

            // ── /help ──
            if (cmd === 'help') {
                const embed = new EmbedBuilder()
                    .setTitle('📚 Arcane Bot — Lista Komend Admina')
                    .setColor(0x2898FA)
                    .setDescription('Oto lista wszystkich dostępnych komend w systemie Arcane:')
                    .addFields(
                        { name: '🔑 `/generatekey [days]`', value: 'Generuje nowy klucz (0 = Lifetime, domyślnie 30 dni)' },
                        { name: '📋 `/userinfo [username]`', value: 'Szczegóły użytkownika (status, IP, HWID, data rejestracji)' },
                        { name: '🔄 `/resetuser [username]`', value: 'Resetuje HWID użytkownika (pozwala zalogować się z nowego PC)' },
                        { name: '🗑️ `/deleteuser [username]`', value: 'Usuwa użytkownika z bazy danych' },
                        { name: '⏳ `/extendkey [username] [days]`', value: 'Przedłuża subskrypcję użytkownika o określoną liczbę dni' },
                        { name: '📜 `/listkeys [filter]`', value: 'Wyświetla listę kluczy (wszystkie, użyte, nieużyte)' },
                        { name: '📊 `/logs`', value: 'Wyświetla 10 ostatnich aktywacji licencji' },
                        { name: '📈 `/stats`', value: 'Statystyki użytkowników, kluczy i aktywacji' },
                        { name: '🚀 `/launchers`', value: 'Lista skompilowanych launcherów z przyciskiem zdalnego destructu' },
                        { name: '💣 `/destructlauncher [buildid]`', value: 'Zdalne zniszczenie danej wersji launchera' },
                        { name: '➕ `/addlauncher [buildid] [name]`', value: 'Dodaje/aktualizuje wersję launchera' },
                        { name: '👥 `/users`', value: 'Wyświetla listę wszystkich użytkowników w bazie' },
                        { name: 'ℹ️ `/help`', value: 'Wyświetla tę wiadomość pomocy' }
                    )
                    .setFooter({ text: 'Arcane Auth System' })
                    .setTimestamp();
                await interaction.editReply({ embeds: [embed] });
            }

            // ── /generatekey ──
            else if (cmd === 'generatekey') {
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
                const user = sql.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username) as any;
                if (!user) return interaction.editReply({ content: `❌ Użytkownik **${username}** nie istnieje.` });

                const daysLeft = user.lifetime ? '∞' : (() => { if (!user.subExpiresAt || now > new Date(user.subExpiresAt)) return '0'; return Math.floor((new Date(user.subExpiresAt).getTime() - now.getTime()) / (1000 * 60 * 60 * 24)); })();
                const statusText = user.lifetime ? '♾️ LIFETIME' : (!user.subExpiresAt || now > new Date(user.subExpiresAt) ? '🔴 WYGASŁA' : `🟢 AKTYWNA (${daysLeft} dni)`);
                const logs = sql.prepare('SELECT * FROM activation_logs WHERE LOWER(username) = LOWER(?) ORDER BY id DESC LIMIT 1').all(username) as any[];

                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle(`📋 Info o użytkowniku: ${user.username}`).setColor(0x2898FA).addFields({ name: '🖥️ HWID', value: user.hwid || 'Nie powiązano', inline: false }, { name: '🌐 IP', value: logs[0]?.ip || 'Brak danych', inline: true }, { name: '📅 Rejestracja', value: formatDate(user.registeredAt), inline: true }, { name: '⏰ Wygaśnięcie', value: user.lifetime ? '♾️ LIFETIME' : formatDate(user.subExpiresAt), inline: true }, { name: '📊 Status', value: statusText, inline: true }).setFooter({ text: 'Arcane Auth System' }).setTimestamp()]});
            }

            // ── /resetuser ──
            else if (cmd === 'resetuser') {
                const username = interaction.options.getString('username');
                const user = sql.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username) as any;
                if (!user) return interaction.editReply({ content: `❌ Użytkownik **${username}** nie istnieje.` });
                const oldHwid = user.hwid || 'Brak';
                sql.prepare('UPDATE users SET hwid = "" WHERE id = ?').run(user.id);
                console.log(`[HWID RESET] User: ${username} | Old HWID: ${oldHwid} | By: ${interaction.user.tag}`);
                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle('🔄 HWID Zresetowany').setColor(0xFFA500).addFields({ name: '👤 Użytkownik', value: username, inline: true }, { name: '🖥️ Stary HWID', value: oldHwid, inline: true }, { name: '✅ Status', value: 'Użytkownik może zalogować się z nowego PC', inline: false }).setFooter({ text: `Reset przez ${interaction.user.tag}` }).setTimestamp()]});
            }

            // ── /deleteuser ──
            else if (cmd === 'deleteuser') {
                const username = interaction.options.getString('username');
                const user = sql.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username) as any;
                if (!user) return interaction.editReply({ content: `❌ Użytkownik **${username}** nie istnieje.` });
                sql.prepare('DELETE FROM users WHERE id = ?').run(user.id);
                console.log(`[USER DELETED] User: ${username} | By: ${interaction.user.tag}`);
                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle('🗑️ Użytkownik Usunięty').setColor(0xFF4444).addFields({ name: '👤 Usunięty użytkownik', value: username, inline: true }, { name: '👮 Przez', value: interaction.user.tag, inline: true }).setFooter({ text: 'Arcane Auth System' }).setTimestamp()]});
            }

            // ── /extendkey ──
            else if (cmd === 'extendkey') {
                const username = interaction.options.getString('username');
                const days = interaction.options.getInteger('days');
                const user = sql.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username) as any;
                if (!user) return interaction.editReply({ content: `❌ Użytkownik **${username}** nie istnieje.` });
                if (user.lifetime) return interaction.editReply({ content: `ℹ️ Użytkownik **${username}** ma już LIFETIME — nie można przedłużyć.` });
                const base = (user.subExpiresAt && new Date(user.subExpiresAt) > now) ? new Date(user.subExpiresAt) : now;
                const newExpiry = new Date(base.getTime() + (days || 30) * 24 * 60 * 60 * 1000);
                sql.prepare('UPDATE users SET subExpiresAt = ? WHERE id = ?').run(newExpiry.toISOString(), user.id);
                console.log(`[SUB EXTENDED] User: ${username} | +${days} days | New expiry: ${newExpiry.toISOString()} | By: ${interaction.user.tag}`);
                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle('⏳ Subskrypcja Przedłużona').setColor(0x00CC66).addFields({ name: '👤 Użytkownik', value: username, inline: true }, { name: '➕ Dodano dni', value: `${days} dni`, inline: true }, { name: '📅 Nowe wygaśnięcie', value: formatDate(newExpiry.toISOString()), inline: false }).setFooter({ text: `Przedłużono przez ${interaction.user.tag}` }).setTimestamp()]});
            }

            // ── /listkeys ──
            else if (cmd === 'listkeys') {
                const filter = interaction.options.getString('filter') || 'all';
                let keys: any[];
                if (filter === 'unused') keys = sql.prepare('SELECT * FROM keys WHERE used = 0 ORDER BY id DESC LIMIT 15').all();
                else if (filter === 'used') keys = sql.prepare('SELECT * FROM keys WHERE used = 1 ORDER BY id DESC LIMIT 15').all();
                else keys = sql.prepare('SELECT * FROM keys ORDER BY id DESC LIMIT 15').all();
                const lines = keys.map(k => `\`${k.code}\` • ${k.durationDays === 0 ? '♾️ LT' : `${k.durationDays}d`} • ${k.used ? '✅ ' + k.usedBy : '⬜ Nieużyty'}`);
                const allKeys = (sql.prepare('SELECT COUNT(*) as count FROM keys').get() as any).count;
                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle(`📜 Klucze licencji (${filter}) — ${keys.length} szt.`).setColor(0x7B68EE).setDescription(lines.length > 0 ? lines.join('\n') : 'Brak kluczy.').setFooter({ text: `Pokazuję max 15 najnowszych | Łącznie: ${allKeys}` }).setTimestamp()]});
            }

            // ── /logs ──
            else if (cmd === 'logs') {
                const logs = sql.prepare('SELECT * FROM activation_logs ORDER BY id DESC LIMIT 10').all() as any[];
                const lines = logs.map((l, i) => `**${i+1}.** \`${l.username}\` • \`${l.ip}\` • HWID: \`${(l.hwid || 'N/A').substring(0,12)}...\` • ${formatDate(l.activatedAt)}`);
                const total = (sql.prepare('SELECT COUNT(*) as count FROM activation_logs').get() as any).count;
                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle('📊 Ostatnie aktywacje licencji').setColor(0x2898FA).setDescription(lines.length > 0 ? lines.join('\n') : 'Brak logów.').setFooter({ text: `Łącznie aktywacji: ${total}` }).setTimestamp()]});
            }

            // ── /stats ──
            else if (cmd === 'stats') {
                const totalUsers = (sql.prepare('SELECT COUNT(*) as count FROM users').get() as any).count;
                const lifetimeUsers = (sql.prepare('SELECT COUNT(*) as count FROM users WHERE lifetime = 1').get() as any).count;
                const activeUsers = (sql.prepare('SELECT COUNT(*) as count FROM users WHERE lifetime = 1 OR (subExpiresAt IS NOT NULL AND subExpiresAt > ?)').get(now.toISOString()) as any).count;
                const expiredUsers = totalUsers - activeUsers;
                const totalKeys = (sql.prepare('SELECT COUNT(*) as count FROM keys').get() as any).count;
                const unusedKeys = (sql.prepare('SELECT COUNT(*) as count FROM keys WHERE used = 0').get() as any).count;
                const totalActivations = (sql.prepare('SELECT COUNT(*) as count FROM activation_logs').get() as any).count;
                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle('📈 Arcane Auth — Statystyki').setColor(0xFFD700).addFields({ name: '👥 Użytkownicy', value: `${totalUsers}`, inline: true }, { name: '🟢 Aktywni', value: `${activeUsers}`, inline: true }, { name: '🔴 Wygasłe', value: `${expiredUsers}`, inline: true }, { name: '♾️ Lifetime', value: `${lifetimeUsers}`, inline: true }, { name: '🔑 Klucze ogółem', value: `${totalKeys}`, inline: true }, { name: '⬜ Nieużyte klucze', value: `${unusedKeys}`, inline: true }, { name: '📊 Aktywacje ogółem', value: `${totalActivations}`, inline: true }).setFooter({ text: 'Arcane Auth System' }).setTimestamp()]});
            }

            // ── /launchers ──
            else if (cmd === 'launchers') {
                const launchers = sql.prepare('SELECT * FROM launchers').all() as any[];
                if (launchers.length === 0) return interaction.editReply({ content: 'ℹ️ **Brak skompilowanych launcherów w bazie.** Użyj `/addlauncher` lub uruchom launcher aby go zarejestrować.' });

                const embed = new EmbedBuilder().setTitle('🚀 Skompilowane Launchery Arcane').setColor(0x7B68EE).setFooter({ text: 'Arcane Auth System • Zdalny Self-Destruct' }).setTimestamp();
                const row = new ActionRowBuilder();
                for (const l of launchers) {
                    const statusText = l.status === 'destructed' ? '💣 **ZDESTRUOWANY**' : '🟢 **AKTYWNY**';
                    const connectedPcCount = l.downloadCount || (JSON.parse(l.activeSessions || '[]')).length || 0;
                    embed.addFields({ name: `📦 ${l.name} (\`${l.buildId}\`)`, value: `Status: ${statusText}\n💻 Pobrane / Aktywne komputery: **${connectedPcCount}**\n📅 Data: ${formatDate(l.compiledAt)}`, inline: false });
                    if (l.status !== 'destructed' && row.components.length < 5) row.addComponents(new ButtonBuilder().setCustomId(`destruct_build_${l.buildId}`).setLabel(`💣 Destruct ${l.buildId}`).setStyle(ButtonStyle.Danger));
                }
                const replyPayload: any = { embeds: [embed] };
                if (row.components.length > 0) replyPayload.components = [row];
                await interaction.editReply(replyPayload);
            }

            // ── /destructlauncher ──
            else if (cmd === 'destructlauncher') {
                const buildId = interaction.options.getString('buildid');
                const launcher = sql.prepare('SELECT * FROM launchers WHERE LOWER(buildId) = LOWER(?)').get(buildId) as any;
                if (!launcher) return interaction.editReply({ content: `❌ Nie znaleziono launchera o ID \`${buildId}\`.` });
                sql.prepare('UPDATE launchers SET status = ? WHERE buildId = ?').run('destructed', buildId);
                console.log(`[LAUNCHER DESTRUCTED] Build: ${buildId} | By: ${interaction.user.tag}`);
                await interaction.editReply({ embeds: [new EmbedBuilder().setTitle('💣 LAUNCHER ZDESTRUOWANY').setColor(0xFF0000).addFields({ name: '📦 Build ID', value: `\`${buildId}\``, inline: true }, { name: '👤 Przez', value: interaction.user.tag, inline: true }, { name: '⚠️ Wynik', value: 'Wszystkie połączone i pobrane launchery na komputerach graczy zostaną automatycznie usunięte i zdestruowane!', inline: false }).setFooter({ text: 'Arcane Remote Destruct Protocol' }).setTimestamp()]});
            }

            // ── /addlauncher ──
            else if (cmd === 'addlauncher') {
                const buildId = interaction.options.getString('buildid');
                const name = interaction.options.getString('name') || `Arcane Launcher ${buildId}`;
                let launcher = sql.prepare('SELECT * FROM launchers WHERE LOWER(buildId) = LOWER(?)').get(buildId) as any;
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
                const users = sql.prepare('SELECT * FROM users ORDER BY id ASC').all() as any[];
                const logs = sql.prepare('SELECT * FROM activation_logs').all() as any[];
                if (users.length === 0) return interaction.editReply({ content: 'ℹ️ **Brak użytkowników w bazie danych.**' });

                const embeds: any[] = [];
                let currentEmbed = new EmbedBuilder().setTitle(`👥 Pełna Lista Użytkowników Arcane (${users.length})`).setColor(0x2898FA).setFooter({ text: 'Arcane Auth System • Pełne Dane Bazy' }).setTimestamp();
                let fieldCount = 0;

                for (const u of users) {
                    if (fieldCount >= 10) {
                        embeds.push(currentEmbed);
                        if (embeds.length >= 5) break;
                        currentEmbed = new EmbedBuilder().setTitle(`👥 Pełna Lista Użytkowników (cd.)`).setColor(0x2898FA).setFooter({ text: 'Arcane Auth System' }).setTimestamp();
                        fieldCount = 0;
                    }

                    const isLt = u.lifetime;
                    const expiry = u.subExpiresAt;
                    const statusText = isLt ? '♾️ LT' : (!expiry || now > new Date(expiry) ? '🔴 WYGASŁA' : `🟢 AKTYWNA (${Math.floor((new Date(expiry).getTime() - now.getTime()) / (1000 * 60 * 60 * 24))}d)`);
                    const actLog = logs.find(l => l.username && l.username.toLowerCase() === u.username.toLowerCase());
                    const ipText = actLog?.ip || 'Brak IP';
                    const hwidText = u.hwid ? `\`${u.hwid.substring(0, 14)}...\`` : '`Brak HWID`';

                    currentEmbed.addFields({ 
                        name: `#${u.id} 👤 ${u.username}`, 
                        value: `Status: ${statusText} | IP: \`${ipText}\` | HWID: ${hwidText}\nWygaśnięcie: ${isLt ? '`♾️ LIFETIME`' : `\`${formatDate(expiry)}\``}`, 
                        inline: false 
                    });
                    fieldCount++;
                }
                if (fieldCount > 0 && embeds.length < 5) {
                    embeds.push(currentEmbed);
                }
                await interaction.editReply({ embeds });
            }

        } catch (err: any) {
            console.error(`[DISCORD BOT] Error in /${cmd}:`, err);
            if (err?.code === 40060 || err?.code === 10062) return;
            const errContent = `❌ Wystąpił błąd podczas wykonywania komendy /${cmd}: ${err?.message || err}`;
            if (interaction.deferred || interaction.replied) {
                await interaction.editReply({ content: errContent }).catch(() => {});
            } else {
                await interaction.reply({ content: errContent, flags: MessageFlags.Ephemeral }).catch(() => {});
            }
        }
    });

    client.on('error', (err: any) => console.error('[DISCORD BOT] Client error:', err));
    client.login(DISCORD_BOT_TOKEN).catch((err: any) => console.error('[DISCORD BOT] Login failed:', err));
}

// -------------------------------------------------------------------
// ElysiaJS App
// -------------------------------------------------------------------
const app = new Elysia()
    .use(cors())

    .onRequest(({ set }) => {
        set.headers['X-Content-Type-Options'] = 'nosniff';
        set.headers['X-Frame-Options'] = 'DENY';
        set.headers['X-XSS-Protection'] = '1; mode=block';
    })

    .get('/', () => ({
        status: 'online',
        server: 'Arcane Auth Backend (SQLite)',
        database: 'SQLite (arcane.db)'
    }))

    .get('/api/health', () => {
        try {
            const keyCount = (sql.prepare('SELECT COUNT(*) as count FROM keys').get() as any).count;
            const userCount = (sql.prepare('SELECT COUNT(*) as count FROM users').get() as any).count;
            return { status: 'ok', db: 'sqlite', keys: keyCount, users: userCount };
        } catch (err: any) {
            return { status: 'error', message: err?.message };
        }
    })

    .post('/api/generatekey', ({ body }: { body: { days?: number } }) => {
        const durationDays = parseInt(String(body?.days ?? 30));
        const isLifetime = durationDays === 0;
        const newKey = generateRandomKey();

        sql.prepare('INSERT INTO keys (code, durationDays, used, createdAt) VALUES (?, ?, 0, ?)').run(newKey, durationDays, new Date().toISOString());

        console.log(`[KEY CREATED] ${newKey} | ${isLifetime ? 'LIFETIME' : durationDays + 'd'}`);
        return { success: true, key: newKey, days: durationDays, lifetime: isLifetime };
    })

    .post('/api/register', async ({ body }: { body: { username?: string; password?: string; key?: string; hwid?: string } }) => {
        const username = body?.username?.trim();
        const password = body?.password;
        const key = body?.key?.trim();
        const hwid = body?.hwid?.trim();

        if (!username || !password || !key) {
            return { success: false, message: "Username, password, and license key are required!" };
        }

        const existingUser = sql.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username);
        if (existingUser) {
            return { success: false, message: "Username is already taken!" };
        }

        const targetKey = sql.prepare('SELECT * FROM keys WHERE code = ? AND used = 0').get(key) as any;
        if (!targetKey) {
            return { success: false, message: "Invalid or already used license key!" };
        }

        sql.prepare('UPDATE keys SET used = 1, usedBy = ?, usedAt = ? WHERE code = ?').run(username, new Date().toISOString(), key);

        const now = new Date();
        const isLifetime = targetKey.durationDays === 0;
        const expiresAt = isLifetime ? null : new Date(now.getTime() + targetKey.durationDays * 24 * 60 * 60 * 1000);
        const hashedPassword = await bcrypt.hash(password, 10);

        sql.prepare('INSERT INTO users (username, password, hwid, subExpiresAt, lifetime, registeredAt) VALUES (?, ?, ?, ?, ?, ?)').run(username, hashedPassword, hwid || '', isLifetime ? null : expiresAt?.toISOString(), isLifetime ? 1 : 0, now.toISOString());
        sql.prepare('INSERT INTO activation_logs (event, username, key, ip, hwid, lifetime, expiresAt, activatedAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run('LICENSE_ACTIVATED', username, key, 'API', hwid || 'Not provided', isLifetime ? 1 : 0, isLifetime ? 'LIFETIME' : expiresAt?.toISOString(), now.toISOString());

        return { success: true, message: "Account registered successfully!", expiresAt: isLifetime ? null : expiresAt?.toISOString(), lifetime: isLifetime };
    })

    .get('/api/logs', () => {
        const logs = sql.prepare('SELECT * FROM activation_logs ORDER BY id DESC LIMIT 50').all();
        return { success: true, total: logs.length, logs };
    })

    .post('/api/login', async ({ body }: { body: { username?: string; password?: string; hwid?: string } }) => {
        const username = body?.username?.trim();
        const password = body?.password;
        const hwid = body?.hwid?.trim();

        if (!username || !password) {
            return { success: false, message: "Username and password are required!" };
        }

        const user = sql.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username) as any;
        if (!user) {
            return { success: false, message: "User not found!" };
        }

        const passwordValid = await bcrypt.compare(password, user.password);
        if (!passwordValid) {
            return { success: false, message: "Invalid password!" };
        }

        if (user.hwid && hwid && user.hwid !== hwid) {
            return { success: false, message: "HWID mismatch! PC not authorized." };
        }

        if (!user.hwid && hwid) {
            sql.prepare('UPDATE users SET hwid = ? WHERE id = ?').run(hwid, user.id);
        }

        const now = new Date();
        if (user.lifetime) {
            return { success: true, message: "Login successful!", username: user.username, expiresAt: null, lifetime: true, daysLeft: -1, hoursLeft: -1 };
        }

        if (!user.subExpiresAt || now > new Date(user.subExpiresAt)) {
            return { success: false, message: "Subscription EXPIRED! Buy new license.", expired: true };
        }

        const subDate = new Date(user.subExpiresAt);
        const diffMs = subDate.getTime() - now.getTime();
        const daysLeft = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        const hoursLeft = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));

        return { success: true, message: "Login successful!", username: user.username, expiresAt: user.subExpiresAt, lifetime: false, daysLeft, hoursLeft };
    })

    .listen(PORT);

console.log(`[SERVER] ElysiaJS + SQLite Server running on port ${PORT}`);
