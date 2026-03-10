#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import struct
import hashlib
import base64
import asyncio
import aiohttp
import logging
import ipaddress
import subprocess
from aiohttp import web

# 环境变量
UUID = os.environ.get('UUID', '7bd180e8-1142-4387-93f5-03e8d750a896')   # 节点UUID
# Komari 配置变量 [cite: 1, 2]
KOMARI_URL = os.environ.get('KOMARI_URL', 'https://komari.afnos86.xx.kg') 
KOMARI_TOKEN = os.environ.get('KOMARI_TOKEN', 'uTQuCs2iParoxjfSxE03Kx')
DOMAIN = os.environ.get('DOMAIN', '')                # 项目分配的域名或反代后的域名 [cite: 1]
SUB_PATH = os.environ.get('SUB_PATH', 'sub')         # 节点订阅token [cite: 1, 2]
NAME = os.environ.get('NAME', '')                    # 节点名称 [cite: 2]
WSPATH = os.environ.get('WSPATH', UUID[:8])          # 节点路径 [cite: 2]
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)  # [cite: 2]
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', '').lower() == 'true' # [cite: 2]
DEBUG = os.environ.get('DEBUG', '').lower() == 'true' # [cite: 2]

# 全局变量
CurrentDomain = DOMAIN
CurrentPort = 443
Tls = 'tls'
ISP = ''

# dns server
DNS_SERVERS = ['8.8.4.4', '1.1.1.1']
BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
    'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
]

# 日志级别
log_level = logging.DEBUG if DEBUG else logging.INFO # [cite: 2, 3]
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 禁用访问日志 [cite: 3]
for log_name in ['aiohttp.access', 'aiohttp.server', 'aiohttp.client', 'aiohttp.internal', 'aiohttp.websocket']:
    logging.getLogger(log_name).setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# --- 基础工具函数 (保持原样) ---
def is_port_available(port, host='0.0.0.0'): # [cite: 3]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False

def find_available_port(start_port, max_attempts=100): # [cite: 3]
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port): # [cite: 4]
            return port
    return None

def is_blocked_domain(host: str) -> bool: # [cite: 4]
    if not host:
        return False
    host_lower = host.lower()
    return any(host_lower == blocked or host_lower.endswith('.' + blocked) 
              for blocked in BLOCKED_DOMAINS)

async def get_isp(): # [cite: 4]
    global ISP
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('https://api.ip.sb/geoip', headers={'User-Agent': 'Mozilla/5.0'}, timeout=3) as resp: # [cite: 5]
                if resp.status == 200: # [cite: 6]
                    data = await resp.json()
                    ISP = f"{data.get('country_code', '')}-{data.get('isp', '')}".replace(' ', '_')
                    return
    except: pass
    try:
        async with aiohttp.ClientSession() as session: # [cite: 7]
            async with session.get('http://ip-api.com/json', headers={'User-Agent': 'Mozilla/5.0'}, timeout=3) as resp:
                if resp.status == 200: # [cite: 8]
                    data = await resp.json()
                    ISP = f"{data.get('countryCode', '')}-{data.get('org', '')}".replace(' ', '_')
                    return
    except: pass
    ISP = 'Unknown'

async def get_ip(): # [cite: 8]
    global CurrentDomain, Tls, CurrentPort # [cite: 9]
    if not DOMAIN or DOMAIN == 'your-domain.com':
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api-ipv4.ip.sb/ip', timeout=5) as resp:
                    if resp.status == 200:
                        ip = await resp.text() # [cite: 10]
                        CurrentDomain = ip.strip()
                        Tls = 'none'
                        CurrentPort = PORT
        except Exception as e:
            logger.error(f'Failed to get IP: {e}') # [cite: 11]
            CurrentDomain = 'change-your-domain.com'
            Tls = 'tls'
            CurrentPort = 443
    else:
        CurrentDomain = DOMAIN
        Tls = 'tls'
        CurrentPort = 443

async def resolve_host(host: str) -> str: # [cite: 11]
    try:
        ipaddress.ip_address(host) # [cite: 12]
        return host
    except: pass
    for dns_server in DNS_SERVERS:
        try:
            async with aiohttp.ClientSession() as session:
                url = f'https://dns.google/resolve?name={host}&type=A'
                async with session.get(url, timeout=5) as resp: # [cite: 13]
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get('Status') == 0 and data.get('Answer'):
                            for answer in data['Answer']: # [cite: 14]
                                if answer.get('type') == 1:
                                    return answer.get('data')
        except: continue # [cite: 15]
    return host

# --- 协议处理类 (保持原样) ---
class ProxyHandler:
    def __init__(self, uuid: str):
        self.uuid = uuid
        self.uuid_bytes = bytes.fromhex(uuid)
        
    async def handle_vless(self, websocket, first_msg: bytes) -> bool: # [cite: 15]
        try:
            if len(first_msg) < 18 or first_msg[0] != 0: # [cite: 16]
                return False
            if first_msg[1:17] != self.uuid_bytes:
                return False
            i = first_msg[17] + 19
            if i + 3 > len(first_msg): # [cite: 17]
                return False
            port = struct.unpack('!H', first_msg[i:i+2])[0]
            i += 2
            atyp = first_msg[i]
            i += 1 # [cite: 18]
            host = ''
            if atyp == 1:  # IPv4
                if i + 4 > len(first_msg): return False # [cite: 19]
                host = '.'.join(str(b) for b in first_msg[i:i+4])
                i += 4
            elif atyp == 2:  # 域名
                if i >= len(first_msg): return False
                host_len = first_msg[i] # [cite: 20]
                i += 1
                if i + host_len > len(first_msg): return False
                host = first_msg[i:i+host_len].decode()
                i += host_len # [cite: 21]
            elif atyp == 3:  # IPv6
                if i + 16 > len(first_msg): return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}' for j in range(i, i+16, 2)) # [cite: 22]
                i += 16
            else: return False
            
            if is_blocked_domain(host): # [cite: 23]
                await websocket.close()
                return False
            await websocket.send_bytes(bytes([0, 0]))
            resolved_host = await resolve_host(host)
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port) # [cite: 24]
                if i < len(first_msg):
                    writer.write(first_msg[i:]) # [cite: 25]
                    await writer.drain()
                async def forward_ws_to_tcp():
                    try:
                        async for msg in websocket: # [cite: 26]
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain() # [cite: 27]
                    except: pass
                    finally:
                        writer.close() # [cite: 28]
                        await writer.wait_closed()
                async def forward_tcp_to_ws():
                    try:
                        while True: # [cite: 29]
                            data = await reader.read(4096)
                            if not data: break # [cite: 30]
                            await websocket.send_bytes(data)
                    except: pass
                await asyncio.gather(forward_ws_to_tcp(), forward_tcp_to_ws()) # [cite: 31]
            except Exception as e: # [cite: 32]
                if DEBUG: logger.error(f"Connection error: {e}")
            return True
        except Exception as e:
            if DEBUG: logger.error(f"VLESS handler error: {e}") # [cite: 33]
            return False

    async def handle_trojan(self, websocket, first_msg: bytes) -> bool: # [cite: 33]
        try:
            if len(first_msg) < 58: return False
            received_hash_bytes = first_msg[:56] # [cite: 34]
            hash_obj1 = hashlib.sha224()
            hash_obj1.update(self.uuid.encode())
            expected_hash_hex1 = hash_obj1.hexdigest()
            hash_obj2 = hashlib.sha224() # [cite: 35]
            hash_obj2.update(UUID.encode())
            expected_hash_hex2 = hash_obj2.hexdigest()
            received_hash_hex = received_hash_bytes.decode('ascii', errors='ignore') # [cite: 36]
            if received_hash_hex != expected_hash_hex1 and received_hash_hex != expected_hash_hex2:
                return False
            offset = 56
            if first_msg[offset:offset+2] == b'\r\n': offset += 2 # [cite: 37]
            cmd = first_msg[offset]
            if cmd != 1: return False
            offset += 1 # [cite: 38]
            atyp = first_msg[offset]
            offset += 1
            host = ''
            if atyp == 1: # [cite: 39]
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4
            elif atyp == 3:
                host_len = first_msg[offset]
                offset += 1
                host = first_msg[offset:offset+host_len].decode() # [cite: 40]
                offset += host_len
            elif atyp == 4:
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}' for j in range(offset, offset+16, 2)) # [cite: 41]
                offset += 16
            else: return False
            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2 # [cite: 42]
            if first_msg[offset:offset+2] == b'\r\n': offset += 2
            if is_blocked_domain(host):
                await websocket.close()
                return False
            resolved_host = await resolve_host(host) # [cite: 43]
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                if offset < len(first_msg): # [cite: 44]
                    writer.write(first_msg[offset:])
                    await writer.drain()
                async def forward_ws_to_tcp():
                    try: # [cite: 45]
                        async for msg in websocket:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data) # [cite: 46]
                                await writer.drain()
                    except: pass
                    finally:
                        writer.close() # [cite: 47]
                        await writer.wait_closed()
                async def forward_tcp_to_ws():
                    try: # [cite: 48]
                        while True:
                            data = await reader.read(4096)
                            if not data: break # [cite: 49]
                            await websocket.send_bytes(data)
                    except: pass
                await asyncio.gather(forward_ws_to_tcp(), forward_tcp_to_ws()) # [cite: 50]
            except Exception as e: # [cite: 51]
                if DEBUG: logger.error(f"Connection error: {e}")
            return True
        except Exception as e:
            if DEBUG: logger.error(f"Tro handler error: {e}") # [cite: 52]
            return False

    async def handle_shadowsocks(self, websocket, first_msg: bytes) -> bool: # [cite: 52]
        try:
            if len(first_msg) < 7: return False # [cite: 53]
            offset = 0
            atyp = first_msg[offset]
            offset += 1
            host = '' # [cite: 54]
            if atyp == 1:
                if offset + 4 > len(first_msg): return False
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4 # [cite: 55]
            elif atyp == 3:
                if offset >= len(first_msg): return False
                host_len = first_msg[offset]
                offset += 1
                if offset + host_len > len(first_msg): return False # [cite: 56]
                host = first_msg[offset:offset+host_len].decode()
                offset += host_len
            elif atyp == 4: # [cite: 57]
                if offset + 16 > len(first_msg): return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}' for j in range(offset, offset+16, 2))
                offset += 16 # [cite: 58]
            else: return False
            if offset + 2 > len(first_msg): return False
            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2 # [cite: 59]
            if is_blocked_domain(host):
                await websocket.close()
                return False
            resolved_host = await resolve_host(host) # [cite: 60]
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                if offset < len(first_msg):
                    writer.write(first_msg[offset:]) # [cite: 61]
                    await writer.drain()
                async def forward_ws_to_tcp():
                    try:
                        async for msg in websocket: # [cite: 62]
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain() # [cite: 63]
                    except: pass
                    finally:
                        writer.close()
                        await writer.wait_closed() # [cite: 64]
                async def forward_tcp_to_ws():
                    try:
                        while True: # [cite: 65]
                            data = await reader.read(4096)
                            if not data: break
                            await websocket.send_bytes(data) # [cite: 66]
                    except: pass
                await asyncio.gather(forward_ws_to_tcp(), forward_tcp_to_ws()) # [cite: 67]
            except Exception as e:
                if DEBUG: logger.error(f"Connection error: {e}") # [cite: 68]
            return True
        except Exception as e:
            if DEBUG: logger.error(f"Shadowsocks handler error: {e}") # [cite: 69]
            return False

# --- 监控部分修改: 替换哪吒为 Komari ---

async def run_komari(): # [cite: 80]
    """单次运行 Komari 代理安装与部署 (保持原 logic 触发频率)"""
    if not KOMARI_URL or not KOMARI_TOKEN: # [cite: 78, 82]
        return
    
    try:
        # 检查是否已运行，防止重复启动 [cite: 80]
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        if 'komari-agent' in result.stdout:
            logger.info('Komari agent is already running, skip...')
            return
    except: pass
    
    # 构建安装命令
    command = f"bash <(curl -sL https://raw.githubusercontent.com/komari-monitor/komari-agent/refs/heads/main/install.sh) -e {KOMARI_URL} -t {KOMARI_TOKEN}"
    
    try:
        # 使用 Popen 以后台进程运行，不阻塞主程序 [cite: 83]
        subprocess.Popen(f"nohup {command} >/dev/null 2>&1 &", shell=True, executable='/bin/bash')
        logger.info('✅ Komari agent started successfully') # [cite: 83]
    except Exception as e:
        logger.error(f'Error running Komari: {e}') # [cite: 83]

# --- Web 处理与主函数 (保持原样) ---

async def websocket_handler(request): # [cite: 69]
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    CUUID = UUID.replace('-', '')
    if f'/{WSPATH}' not in request.path:
        await ws.close(); return ws
    
    proxy = ProxyHandler(CUUID)
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=5) # [cite: 70]
        if first_msg.type != aiohttp.WSMsgType.BINARY:
            await ws.close(); return ws
        
        msg_data = first_msg.data
        if len(msg_data) > 17 and msg_data[0] == 0: # [cite: 70]
            if await proxy.handle_vless(ws, msg_data): return ws # [cite: 71]
        if len(msg_data) >= 58:
            if await proxy.handle_trojan(ws, msg_data): return ws
        if len(msg_data) > 0 and msg_data[0] in (1, 3, 4): # [cite: 72]
            if await proxy.handle_shadowsocks(ws, msg_data): return ws
        await ws.close()
    except Exception as e:
        if DEBUG: logger.error(f"WebSocket handler error: {e}") # [cite: 73]
        await ws.close()
    return ws

async def http_handler(request): # [cite: 73]
    if request.path == '/':
        try:
            with open('index.html', 'r', encoding='utf-8') as f:
                return web.Response(text=f.read(), content_type='text/html') # [cite: 74]
        except:
            return web.Response(text='Hello world!', content_type='text/html')
    
    elif request.path == f'/{SUB_PATH}': # [cite: 74]
        await get_isp(); await get_ip()
        name_part = f"{NAME}-{ISP}" if NAME else ISP
        tls_param = 'tls' if Tls == 'tls' else 'none'
        vless_url = f"vless://{UUID}@{CurrentDomain}:{CurrentPort}?encryption=none&security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"
        subscription = f"{vless_url}"
        return web.Response(text=base64.b64encode(subscription.encode()).decode() + '\n', content_type='text/plain') # [cite: 76]
    
    return web.Response(status=404, text='Not Found\n')

async def add_access_task(): # [cite: 83]
    if not AUTO_ACCESS or not DOMAIN: return
    try:
        async with aiohttp.ClientSession() as session:
            await session.post("https://oooo.serv00.net/add-url", # [cite: 84]
                             json={"url": f"https://{DOMAIN}/{SUB_PATH}"},
                             headers={'Content-Type': 'application/json'})
    except: pass

async def main(): # [cite: 85]
    actual_port = PORT
    if not is_port_available(actual_port): # [cite: 86]
        new_port = find_available_port(actual_port + 1)
        if new_port: actual_port = new_port
        else: sys.exit(1)
    
    app = web.Application()
    app.router.add_get('/', http_handler)
    app.router.add_get(f'/{SUB_PATH}', http_handler)
    app.router.add_get(f'/{WSPATH}', websocket_handler)
    
    runner = web.AppRunner(app) # 
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', actual_port)
    await site.start()
    logger.info(f"✅ server is running on port {actual_port}")
    
    # 在主任务中启动 Komari 部署 
    asyncio.create_task(run_komari())
    await add_access_task()
    
    try:
        await asyncio.Future() # 
    except KeyboardInterrupt: pass # [cite: 88]
    finally: await runner.cleanup()

if __name__ == '__main__':
    try:
        asyncio.run(main()) # [cite: 88]
    except KeyboardInterrupt:
        print("\nServer stopped by user")
