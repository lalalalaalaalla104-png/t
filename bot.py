import os
import asyncio
import aiohttp
from threading import Thread
from flask import Flask
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.client.telegram import TelegramAPIServer
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.types import CallbackQuery

# --- БЕРЕМ КЛЮЧИ ИЗ ПЕРЕМЕННЫХ ОКРУЖЕНИЯ (ДЛЯ RENDER) ---
BOT_TOKEN = os.getenv('BOT_TOKEN')
VT_API_KEY = os.getenv('VT_API_KEY')
ABUSE_API_KEY = os.getenv('ABUSE_API_KEY')
PROXY_URL = os.getenv('PROXY_URL')

# --- НАСТРОЙКА ПРОКСИ CLOUDFLARE ---
api_server = TelegramAPIServer.from_base(PROXY_URL)
session = AiohttpSession(api=api_server)
bot = Bot(token=BOT_TOKEN, session=session)
dp = Dispatcher()

# --- ФУНКЦИИ ПРОВЕРКИ ---

async def check_ip(ip: str):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {'Accept': 'application/json', 'Key': ABUSE_API_KEY}
    async with aiohttp.ClientSession() as session_http:
        async with session_http.get(url, headers=headers) as resp:
            if resp.status == 200:
                d = (await resp.json())['data']
                return f"🌐 **IP:** `{d['ipAddress']}`\n🏳️ **Страна:** {d['countryCode']}\n📊 **Злоупотребления:** {d['abuseConfidenceScore']}%"
            return "❌ Ошибка проверки IP."

async def check_domain(domain: str):
    url = f"https://rdap.org/domain/{domain}"
    async with aiohttp.ClientSession() as session_http:
        async with session_http.get(url) as resp:
            if resp.status == 200:
                data = await resp.json()
                events = {e['eventAction']: e['eventDate'][:10] for e in data.get('events', [])}
                return f"🌐 **Домен:** `{domain}`\n📅 **Создан:** {events.get('registration', 'Н/Д')}\n⏳ **Истекает:** {events.get('expiration', 'Н/Д')}"
            return "❌ Домен не найден или ошибка RDAP."

async def check_email(email: str):
    return "☕ Овнер бота потратил все деньги на кофе и не купил API для проверки email. Попробуй позже (или никогда)."

async def check_url_vt(url_to_check: str):
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY}
    async with aiohttp.ClientSession() as session_http:
        async with session_http.post(vt_url, headers=headers, data={"url": url_to_check}) as resp:
            if resp.status != 200: return "❌ Ошибка VirusTotal (лимит или ключ)."
            analysis_id = (await resp.json())['data']['id']
            await asyncio.sleep(3)
            res_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            async with session_http.get(res_url, headers=headers) as resp2:
                if resp2.status == 200:
                    stats = (await resp2.json())['data']['attributes']['stats']
                    return f"🔗 **Ссылка:** {url_to_check}\n🦠 **Вредоносных:** {stats.get('malicious', 0)}\n✅ **Безопасных:** {stats.get('harmless', 0)}"
                return "❌ Ошибка получения результата."

async def check_file_vt(file_id: str):
    file_info = await bot.get_file(file_id)
    file_path = file_info.file_path
    file_url = f"https://api.telegram.org/file/bot{BOT_TOKEN}/{file_path}"
    
    async with aiohttp.ClientSession() as session_http:
        async with session_http.get(file_url) as resp:
            if resp.status != 200: return "❌ Ошибка скачивания файла."
            file_data = await resp.read()
    
    vt_url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    form = aiohttp.FormData()
    form.add_field('file', file_data, filename='file.bin')
    
    async with aiohttp.ClientSession() as session_http:
        async with session_http.post(vt_url, headers=headers, data=form) as resp:
            if resp.status != 200: 
                return "❌ Ошибка VirusTotal (возможно, файл слишком большой или лимит)."
            analysis_id = (await resp.json())['data']['id']
            await asyncio.sleep(5)
            res_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            async with session_http.get(res_url, headers=headers) as resp2:
                if resp2.status == 200:
                    stats = (await resp2.json())['data']['attributes']['stats']
                    return f"📁 **Файл проверен.**\n🦠 **Вредоносных:** {stats.get('malicious', 0)}\n✅ **Безопасных:** {stats.get('harmless', 0)}"
                return "❌ Ошибка получения результата (файл еще анализируется)."

# --- КНОПКИ И ОБРАБОТЧИКИ ---

def get_main_menu():
    builder = InlineKeyboardBuilder()
    builder.button(text="🌐 Проверить IP", callback_data="menu_ip")
    builder.button(text="🔗 Проверить ссылку", callback_data="menu_url")
    builder.button(text="📧 Проверить Email", callback_data="menu_email")
    builder.button(text="🏠 Проверить домен", callback_data="menu_domain")
    builder.button(text="📁 Проверить файл", callback_data="menu_file")
    builder.adjust(2)
    return builder.as_markup()

@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer("👋 Привет! Я OSINT-бот. Выбери действие:", reply_markup=get_main_menu())

@dp.callback_query(F.data.startswith("menu_"))
async def handle_menu(call: CallbackQuery):
    actions = {"menu_ip": "IP-адрес", "menu_url": "Ссылку", "menu_email": "Email", "menu_domain": "Домен", "menu_file": "Файл (документом)"}
    await call.message.edit_text(f"Отправь мне {actions[call.data]}")
    await call.answer()

@dp.message(F.document)
async def handle_file(message: types.Message):
    if message.document.file_size > 32 * 1024 * 1024:
        await message.answer("❌ Файл слишком большой (макс 32 МБ).")
        return
    await message.answer("⏳ Скачиваю и проверяю файл (займет ~10 секунд)...")
    result = await check_file_vt(message.document.file_id)
    await message.answer(result, parse_mode="Markdown")

@dp.message()
async def handle_text(message: types.Message):
    text = message.text.strip()
    if text.count('.') == 3 and all(p.isdigit() for p in text.split('.')):
        await message.answer("⏳ Проверяю IP...")
        await message.answer(await check_ip(text), parse_mode="Markdown")
    elif text.startswith('http://') or text.startswith('https://'):
        await message.answer("⏳ Проверяю ссылку...")
        await message.answer(await check_url_vt(text), parse_mode="Markdown")
    elif '@' in text and '.' in text:
        await message.answer("⏳ Проверяю Email...")
        await message.answer(await check_email(text), parse_mode="Markdown")
    elif '.' in text and not text.startswith('http'):
        await message.answer("⏳ Проверяю домен...")
        await message.answer(await check_domain(text), parse_mode="Markdown")
    else:
        await message.answer("🤔 Не понял. Отправь IP, ссылку, email, домен или файл.")

async def main():
    print("Бот запущен...")
    await dp.start_polling(bot)

# --- FLASK ДЛЯ RENDER (ЧТОБЫ ОН НЕ РУГАЛСЯ НА ПОРТЫ) ---
app = Flask(__name__)

@app.route('/')
@app.route('/health')
def health():
    return "Bot is running", 200

def run_bot():
    asyncio.run(main())

if __name__ == "__main__":
    t = Thread(target=run_bot)
    t.start()
    
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)



