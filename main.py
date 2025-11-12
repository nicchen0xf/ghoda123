import asyncio
import json
import os
import random
import ssl
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
import urllib3
from aiohttp import web
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from Pb2 import (
    DEcwHisPErMsG_pb2,
    MajoRLoGinrEq_pb2,
    MajoRLoGinrEs_pb2,
    PorTs_pb2,
    sQ_pb2,
)
from cfonts import render

from xC4 import (
    AutH_Chat,
    AuthClan,
    DecodE_HeX,
    DeCode_PackEt,
    EnC_PacKeT,
    Emote_k,
    ExiT,
    GeTSQDaTa,
    GenJoinSquadsPacket,
    OpEnSq,
    SEnd_InV,
    cHSq,
    xSEndMsg,
    xSEndMsgsQ,
)
from xHeaders import equie_emote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Constants & Utilities
# ---------------------------------------------------------------------------

BASE_HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/x-www-form-urlencoded",
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": "OB51",
}

CONFIG_DIR = os.path.join("config")
BD_ACCOUNTS_FILE = os.path.join(CONFIG_DIR, "accounts_bd.json")
PK_ACCOUNTS_FILE = os.path.join(CONFIG_DIR, "accounts_pk.json")


class BotStatus(Enum):
    OFFLINE = "offline"
    CONNECTING = "connecting"
    ONLINE = "online"
    IDLE = "idle"
    BUSY = "busy"
    IN_SQUAD = "in_squad"
    ERROR = "error"


def _copy_headers() -> Dict[str, str]:
    """Return a fresh copy of the base headers to avoid shared mutations."""
    return dict(BASE_HEADERS)


# ---------------------------------------------------------------------------
# Network / Protocol helpers (adapted from original single-bot implementation)
# ---------------------------------------------------------------------------


async def Ua() -> str:
    versions = [
        "4.0.18P6",
        "4.0.19P7",
        "4.0.20P1",
        "4.1.0P3",
        "4.1.5P2",
        "4.2.1P8",
        "4.2.3P1",
        "5.0.1B2",
        "5.0.2P4",
        "5.1.0P1",
        "5.2.0B1",
        "5.2.5P3",
        "6.0.0B1",
        "6.0.1P2",
        "6.1.0P1",
        "6.2.0B1",
        "7.0.0B1",
        "7.1.0P1",
    ]
    models = [
        "SM-G973F",
        "SM-G975F",
        "SM-G988B",
        "SM-G991B",
        "SM-G996B",
        "SM-G998B",
        "Pixel 4",
        "Pixel 5",
        "Pixel 6",
        "OnePlus 8",
        "OnePlus 9",
        "Mi 11",
    ]
    androids = ["9", "10", "11", "12", "13"]
    langs = ["en-US", "en-GB", "zh-CN", "ja-JP", "ko-KR", "es-ES", "fr-FR"]
    countries = ["US", "GB", "CN", "JP", "KR", "ES", "FR", "DE", "IT", "BR"]

    version = random.choice(versions)
    model = random.choice(models)
    android = random.choice(androids)
    lang = random.choice(langs)
    country = random.choice(countries)
    return f"GarenaMSDK/{version}({model};Android {android};{lang};{country};)"


async def GeNeRaTeAccEss(uid: str, password: str) -> Tuple[Optional[str], Optional[str]]:
    """Authenticate and obtain open_id + access token for a bot account."""
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067",
    }

    headers = {
        "Host": "ffmconnect.live.gop.garenanow.com",
        "User-Agent": await Ua(),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    
    timeout = aiohttp.ClientTimeout(total=15)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            async with session.post(url, headers=headers, data=data) as response:
                if response.status != 200:
                    return None, None
                
                resp_json = await response.json()
                open_id = resp_json.get("open_id")
                access_token = resp_json.get("access_token")
                if open_id and access_token:
                    return open_id, access_token
                return None, None
        except (asyncio.TimeoutError, aiohttp.ClientConnectorError):
            return None, None


async def encrypted_proto(encoded_hex: bytes) -> bytes:
    key = b"Yg&tc%DEuh6%Zc^8"
    iv = b"6oyZDr22E3ychjM%"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload


async def EncRypTMajoRLoGin(open_id: str, access_token: str) -> bytes:
    """Build and encrypt the MajorLogin protobuf payload."""
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(time.strftime("%Y-%m-%d %H:%M:%S"))
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.118.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = (
        "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    )
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return await encrypted_proto(string)


async def MajorLogin(payload: bytes) -> Optional[bytes]:
    url = "https://loginbp.common.ggbluefox.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    headers = _copy_headers()

    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=headers, ssl=ssl_context) as response:
            if response.status == 200:
                return await response.read()
            return None


async def GetLoginData(base_url: str, payload: bytes, token: str) -> Optional[bytes]:
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    headers = _copy_headers()
    headers["User-Agent"] = await Ua()
    headers["Authorization"] = f"Bearer {token}"

    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=headers, ssl=ssl_context) as response:
            if response.status == 200:
                return await response.read()
            return None


async def DecRypTMajoRLoGin(payload: bytes) -> MajoRLoGinrEs_pb2.MajorLoginRes:
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(payload)
    return proto


async def DecRypTLoGinDaTa(payload: bytes) -> PorTs_pb2.GetLoginData:
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(payload)
    return proto


async def DecodeWhisperMessage(hex_packet: str) -> DEcwHisPErMsG_pb2.DecodeWhisper:
    packet = bytes.fromhex(hex_packet)
    proto = DEcwHisPErMsG_pb2.DecodeWhisper()
    proto.ParseFromString(packet)
    return proto
    

async def decode_team_packet(hex_packet: str) -> sQ_pb2.recieved_chat:
    packet = bytes.fromhex(hex_packet)
    proto = sQ_pb2.recieved_chat()
    proto.ParseFromString(packet)
    return proto
    

async def xAuThSTarTuP(target: int, token: str, timestamp: int, key: bytes, iv: bytes) -> str:
    uid_hex = hex(target)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]

    if uid_length == 9:
        headers = "0000000"
    elif uid_length == 8:
        headers = "00000000"
    elif uid_length == 10:
        headers = "000000"
    elif uid_length == 7:
        headers = "000000000"
    else:
        print("Unexpected UID length when building auth startup packet")
        headers = "0000000"

    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"
     

# ---------------------------------------------------------------------------
# Bot runtime definition
# ---------------------------------------------------------------------------


@dataclass
class BotRuntime:
    uid: str
    password: str
    server: str
    index: int
    manager: "MultiBotController"
    status: BotStatus = BotStatus.OFFLINE
    account_uid: Optional[int] = None
    account_name: str = ""
    region: str = ""
    key: Optional[bytes] = None
    iv: Optional[bytes] = None
    token: Optional[str] = None
    url: Optional[str] = None
    timestamp: Optional[int] = None
    online_writer: Optional[asyncio.StreamWriter] = None
    whisper_writer: Optional[asyncio.StreamWriter] = None
    command_queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    tasks: List[asyncio.Task] = field(default_factory=list)
    ready_event: asyncio.Event = field(default_factory=asyncio.Event)
    last_error: Optional[str] = None
    busy_reason: Optional[str] = None
    reconnect_attempts: int = 0
    busy_until: float = 0.0
    last_activity: Optional[datetime] = None
    current_squad: Optional[str] = None
    squad_joined_time: Optional[datetime] = None
    wave_id: Optional[str] = None
    login_reported: bool = False
    owner_uid: Optional[str] = None
    session_id: Optional[str] = None  # Track which user session controls this bot

    async def run(self):
        delay = 5
        while not self.manager.shutdown_event.is_set():
            try:
                await self._login_and_connect()
                await self._lifecycle_loop()
                delay = 5  # reset on successful cycle
            except asyncio.CancelledError:
                await self._cleanup()
                raise
            except Exception as exc:
                self.last_error = str(exc)
                self.status = BotStatus.ERROR
                if not self.login_reported:
                    await self.manager.on_bot_login_failed(self, str(exc))
                    self.login_reported = True
                await self._cleanup()
                if self.manager.shutdown_event.is_set():
                    break
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60)

    def mark_busy(self, duration: float, reason: Optional[str] = None):
        self.status = BotStatus.BUSY
        self.busy_reason = reason or self.busy_reason
        self.busy_until = time.monotonic() + duration
        self.last_activity = datetime.now(UTC)

    def refresh_busy_state(self):
        if self.status == BotStatus.BUSY and self.busy_until and time.monotonic() > self.busy_until:
            if self.command_queue.empty():
                self.status = BotStatus.IDLE
                self.busy_reason = None

    async def _login_and_connect(self):
        self.status = BotStatus.CONNECTING
        self.ready_event.clear()
        open_id, access_token = await GeNeRaTeAccEss(self.uid, self.password)
        if not open_id or not access_token:
            raise RuntimeError("Failed to obtain access token")

        payload = await EncRypTMajoRLoGin(open_id, access_token)
        major_login_response = await MajorLogin(payload)
        if not major_login_response:
            raise RuntimeError("Major login failed")

        auth_proto = await DecRypTMajoRLoGin(major_login_response)
        self.url = auth_proto.url
        self.token = auth_proto.token
        self.account_uid = auth_proto.account_uid
        self.key = auth_proto.key
        self.iv = auth_proto.iv
        self.region = auth_proto.region
        self.timestamp = auth_proto.timestamp

        login_data_bytes = await GetLoginData(self.url, payload, self.token)
        if not login_data_bytes:
            raise RuntimeError("Failed to retrieve login data")

        login_data = await DecRypTLoGinDaTa(login_data_bytes)
        online_port = login_data.Online_IP_Port
        chat_port = login_data.AccountIP_Port
        self.account_name = login_data.AccountName or f"Bot_{self.uid[-4:]}"

        online_ip, online_port_str = online_port.rsplit(":", 1)
        chat_ip, chat_port_str = chat_port.rsplit(":", 1)
        online_ip = online_ip.strip("[]")
        chat_ip = chat_ip.strip("[]")

        auth_token = await xAuThSTarTuP(int(self.account_uid), self.token, int(self.timestamp), self.key, self.iv)

        # Equip emote set just like single bot
        try:
            equie_emote(self.token, self.url)
        except Exception:
            pass

        await self.manager.on_bot_authenticated(self)

        self.tasks = [
            asyncio.create_task(self._tcp_chat(chat_ip, chat_port_str, auth_token, login_data)),
            asyncio.create_task(self._tcp_online(online_ip, online_port_str, auth_token)),
            asyncio.create_task(self._command_processor()),
        ]

        await self.ready_event.wait()
        self.status = BotStatus.IDLE
        self.last_activity = datetime.now(UTC)

    async def _lifecycle_loop(self):
        done, pending = await asyncio.wait(
            self.tasks,
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()

        await self._cleanup()

    async def _cleanup(self):
        for writer in (self.online_writer, self.whisper_writer):
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
        self.online_writer = None
        self.whisper_writer = None
        self.ready_event.clear()
        self.tasks.clear()
        await self.manager.on_bot_disconnected(self)

    async def _tcp_online(self, ip: str, port: str, auth_token: str):
        reader, writer = await asyncio.open_connection(ip, int(port))
        self.online_writer = writer
        writer.write(bytes.fromhex(auth_token))
        await writer.drain()

        while not self.manager.shutdown_event.is_set():
            data = await reader.read(4096)
            if not data:
                break
            await self._handle_online_packet(data)

    async def _tcp_chat(self, ip: str, port: str, auth_token: str, login_data):
        reader, writer = await asyncio.open_connection(ip, int(port))
        self.whisper_writer = writer
        writer.write(bytes.fromhex(auth_token))
        await writer.drain()
        self.ready_event.set()

        if getattr(login_data, "Clan_ID", None):
            try:
                clan_packet = await AuthClan(login_data.Clan_ID, login_data.Clan_Compiled_Data, self.key, self.iv)
                await self._send_chat_packet(clan_packet)
            except Exception:
                pass

        while not self.manager.shutdown_event.is_set():
            data = await reader.read(4096)
            if not data:
                break
            await self._handle_chat_packet(data)

    async def _handle_online_packet(self, data: bytes):
        hex_data = data.hex()
        if hex_data.startswith("0500") and len(hex_data) > 1000:
            try:
                packet_json = await DeCode_PackEt(hex_data[10:])
                if not packet_json:
                    return
                payload = json.loads(packet_json)
                owner_uid, chat_code, _ = await GeTSQDaTa(payload)
                join_packet = await AutH_Chat(3, owner_uid, chat_code, self.key, self.iv)
                await self._send_chat_packet(join_packet)

                message = "Hi! I am a bot from Byte Force"
                msg_packet = await self._build_message(0, message, owner_uid, owner_uid)
                await self._send_chat_packet(msg_packet)
            except Exception:
                pass

    async def _handle_chat_packet(self, data: bytes):
        hex_data = data.hex()
        if hex_data.startswith("120000"):
            try:
                response = await DecodeWhisperMessage(hex_data[10:])
                incoming = response.Data.msg.lower()
                if incoming in ("hi", "hello", "help"):
                    message = "Use the web panel to control me!\n[C][FF2400]DISCORD : Byte Force"
                    packet = await self._build_message(
                        response.Data.chat_type,
                        message,
                        response.Data.uid,
                        response.Data.Chat_ID,
                    )
                    await self._send_chat_packet(packet)
            except Exception:
                pass

    async def _build_message(self, chat_type: int, message: str, uid: int, chat_id: int):
        if chat_type == 0:
            return await xSEndMsgsQ(message, chat_id, self.key, self.iv)
        if chat_type == 1:
            return await xSEndMsg(message, 1, chat_id, chat_id, self.key, self.iv)
        return await xSEndMsg(message, 2, uid, uid, self.key, self.iv)

    async def _send_online_packet(self, packet: bytes):
        if not self.online_writer:
            raise RuntimeError("Online writer is not ready")
        self.online_writer.write(packet)
        await self.online_writer.drain()

    async def _send_chat_packet(self, packet: bytes):
        if not self.whisper_writer:
            raise RuntimeError("Chat writer is not ready")
        self.whisper_writer.write(packet)
        await self.whisper_writer.drain()

    async def _command_processor(self):
        while not self.manager.shutdown_event.is_set():
            command = await self.command_queue.get()
            action = command.get("action")
            success = False
            try:
                if action == "emote":
                    success = await self._handle_emote(command)
                elif action == "emote_batch":
                    success = await self._handle_emote_batch(command)
                elif action == "freestyle_emote":
                    success = await self._handle_freestyle_emote(command)
                elif action == "join_squad":
                    success = await self._handle_join_squad(command)
                elif action == "quick_invite":
                    success = await self._handle_quick_invite(command)
                elif action == "leave_squad":
                    success = await self._handle_leave_squad(command)
                else:
                    self.manager.log(f"[{self.uid}] ⚠️ Unknown action: {action}")
            except Exception as exc:
                self.last_error = str(exc)
                self.manager.log(f"[{self.uid}] ❌ Command '{action}' failed: {exc}")
            finally:
                await self.manager.on_command_complete(self, action, success)
                self.command_queue.task_done()

    async def _handle_emote(self, command: Dict) -> bool:
        emote_id = command.get("emote_id")
        player_ids = command.get("player_ids", [])
        duration = command.get("duration", 30)
        if not emote_id or not player_ids:
            raise ValueError("Emote command missing data")
        if not self.online_writer:
            raise RuntimeError("Online connection is not ready")

        for player_id in player_ids:
            try:
                target = int(player_id)
            except (TypeError, ValueError):
                continue
            packet = await Emote_k(target, emote_id, self.key, self.iv, self.region)
            await self._send_online_packet(packet)
            await asyncio.sleep(0.2)

        self.mark_busy(duration, reason="emote")
        return True
            
    async def _handle_emote_batch(self, command: Dict) -> bool:
        assignments = command.get("assignments", [])
        duration = command.get("duration", 45)
        if not assignments:
            raise ValueError("Batch command missing assignments")
        if not self.online_writer:
            raise RuntimeError("Online connection is not ready")

        for assignment in assignments:
            player_id = assignment.get("player_id")
            emote_id = assignment.get("emote_id")
            if not player_id or not emote_id:
                continue
            try:
                target = int(player_id)
            except (TypeError, ValueError):
                continue
            packet = await Emote_k(target, emote_id, self.key, self.iv, self.region)
            await self._send_online_packet(packet)
            await asyncio.sleep(0.2)

        self.mark_busy(duration, reason="emote_batch")
        return True

    async def _handle_freestyle_emote(self, command: Dict) -> bool:
        emote_id = command.get("emote_id")
        player_ids = command.get("player_ids", [])
        team_code = self.manager._normalize_team_code(command.get("team_code"))
        owner_uid = self.manager._normalize_owner_uid(
            command.get("main_uid") or command.get("mainUid")
        )
        if not emote_id or not player_ids or not team_code:
            raise ValueError("Freestyle emote command missing data")
        if not self.online_writer:
            raise RuntimeError("Online connection is not ready")

        join_delay = max(0.0, float(command.get("join_delay", 0.0)))
        emote_delay = max(0.0, float(command.get("emote_delay", 0.0)))
        post_delay = max(0.0, float(command.get("post_delay", 0.0)))
        duration = command.get("duration", 5)

        joined_squad = False

        try:
            join_packet = await GenJoinSquadsPacket(team_code, self.key, self.iv)
            await self._send_online_packet(join_packet)
            self.current_squad = team_code
            self.squad_joined_time = datetime.now(UTC)
            self.owner_uid = owner_uid
            await self.manager.on_bot_joined_squad(self, team_code, owner_uid)
            joined_squad = True

            if join_delay > 0:
                await asyncio.sleep(join_delay)

            for player_id in player_ids:
                try:
                    target = int(player_id)
                except (TypeError, ValueError):
                    continue
                packet = await Emote_k(target, emote_id, self.key, self.iv, self.region)
                await self._send_online_packet(packet)
                if emote_delay > 0:
                    await asyncio.sleep(emote_delay)

            if post_delay > 0:
                await asyncio.sleep(post_delay)
        finally:
            if joined_squad:
                try:
                    leave_packet = await ExiT(int(self.account_uid), self.key, self.iv)
                    await self._send_online_packet(leave_packet)
                finally:
                    await self.manager.on_bot_left_squad(self)

        self.mark_busy(duration, reason="freestyle_emote")
        return True

    async def _handle_join_squad(self, command: Dict) -> bool:
        team_code = self.manager._normalize_team_code(command.get("team_code"))
        owner_uid = self.manager._normalize_owner_uid(command.get("main_uid") or command.get("mainUid"))
        duration = command.get("duration", 10)
        if not team_code:
            raise ValueError("Join squad requires team_code")
        if not self.online_writer:
            raise RuntimeError("Online connection is not ready")

        packet = await GenJoinSquadsPacket(team_code, self.key, self.iv)
        await self._send_online_packet(packet)
        self.current_squad = team_code
        self.squad_joined_time = datetime.now(UTC)
        self.owner_uid = owner_uid
        self.mark_busy(duration, reason=f"in_squad:{team_code}")
        await self.manager.on_bot_joined_squad(self, team_code, owner_uid)
        return True

    async def _handle_leave_squad(self, command: Dict) -> bool:
        if not self.online_writer:
            raise RuntimeError("Online connection is not ready")
        exit_packet = await ExiT(int(self.account_uid), self.key, self.iv)
        await self._send_online_packet(exit_packet)
        await self.manager.on_bot_left_squad(self)
        self.busy_reason = None
        self.owner_uid = None
        return True

    async def _handle_quick_invite(self, command: Dict) -> bool:
        player_id = command.get("player_id")
        duration = command.get("duration", 15)
        if not player_id:
            raise ValueError("Quick invite requires player_id")
        if not self.online_writer:
            raise RuntimeError("Online connection is not ready")

        packet_open = await OpEnSq(self.key, self.iv, self.region)
        await self._send_online_packet(packet_open)
        await asyncio.sleep(0.5)
        packet_ch = await cHSq(5, player_id, self.key, self.iv, self.region)
        await self._send_online_packet(packet_ch)
        await asyncio.sleep(0.5)
        packet_inv = await SEnd_InV(5, player_id, self.key, self.iv, self.region)
        await self._send_online_packet(packet_inv)
        self.mark_busy(duration, reason="quick_invite")
        return True


# ---------------------------------------------------------------------------
# Multi bot controller
# ---------------------------------------------------------------------------


class MultiBotController:
    def __init__(self):
        self.bots: List[BotRuntime] = []
        self.bots_by_server: Dict[str, List[BotRuntime]] = {"BD": [], "PK": []}
        self.lock = asyncio.Lock()
        self.shutdown_event = asyncio.Event()
        self.tasks: List[asyncio.Task] = []
        self.wave_size = 6
        self.wave_delay = 8  # seconds between waves to avoid auth throttling
        self.wave_tracker: Dict[str, Dict[str, Any]] = {}
        self._wave_header_printed = False
        self._team_code_keys = ("team_code", "teamCode", "teamcode", "squad_code", "squadCode", "squad")
        self._owner_uid_keys = (
            "main_uid",
            "mainUid",
            "mainUID",
            "owner_uid",
            "ownerUid",
            "account_uid",
            "accountUid",
        )
        self.squad_registry: Dict[str, BotRuntime] = {}
        self.owner_registry: Dict[str, BotRuntime] = {}
        self.session_registry: Dict[str, BotRuntime] = {}  # Track which session controls which bot

    def log(self, message: str):
        print(message)

    async def load_accounts(self):
        await self._load_server_accounts(BD_ACCOUNTS_FILE, "BD", limit=40)
        await self._load_server_accounts(PK_ACCOUNTS_FILE, "PK", limit=35)

    async def _load_server_accounts(self, path: str, server: str, limit: int):
        if not os.path.exists(path):
            self.log(f"⚠️ Accounts file missing: {path}")
            return
        with open(path, "r", encoding="utf-8") as f:
            accounts = json.load(f)
        for idx, account in enumerate(accounts[:limit], start=1):
            bot = BotRuntime(
                uid=str(account["uid"]),
                password=account["password"],
                server=server,
                index=idx,
                manager=self,
            )
            self.bots.append(bot)
            if server in self.bots_by_server:
                self.bots_by_server[server].append(bot)
            else:
                self.bots_by_server[server] = [bot]
        self.log(f"✅ Loaded {min(len(accounts), limit)} accounts for {server} server")

    def _refresh_busy_states(self):
        for bot in self.bots:
            bot.refresh_busy_state()

    @staticmethod
    def _bot_is_available(bot: Optional[BotRuntime], preferred_server: Optional[str]) -> bool:
        if not bot or not bot.online_writer:
            return False
        if preferred_server and bot.server.lower() != preferred_server.lower():
            return False
        return True

    @staticmethod
    def _normalize_team_code(value: Optional[Any]) -> Optional[str]:
        if value is None:
            return None
        code = str(value).strip()
        return code or None

    @staticmethod
    def _normalize_owner_uid(value: Optional[Any]) -> Optional[str]:
        if value is None:
            return None
        uid = str(value).strip()
        return uid or None

    def _extract_team_code(self, payload: Dict) -> Optional[str]:
        for key in self._team_code_keys:
            if key in payload:
                return self._normalize_team_code(payload.get(key))
        return None

    def _extract_owner_uid(self, payload: Dict) -> Optional[str]:
        for key in self._owner_uid_keys:
            if key in payload:
                return self._normalize_owner_uid(payload.get(key))
        return None

    async def start_all(self):
        server_order = ["BD", "PK"]
        server_summaries = {}
        
        for server in server_order:
            server_bots = self.bots_by_server.get(server, [])
            if not server_bots:
                self.log(f"[{server}] No accounts queued")
                continue

            total = len(server_bots)
            waves = (total + self.wave_size - 1) // self.wave_size
            if waves == 0:
                continue

            # Track all wave labels for this server
            server_wave_labels = []
            
            for wave_index in range(waves):
                start = wave_index * self.wave_size
                end = min(start + self.wave_size, total)
                wave = server_bots[start:end]
                wave_label = f"{server}-wave-{wave_index + 1}"
                server_wave_labels.append(wave_label)
                self._init_wave(wave_label, server, wave_index + 1, waves, wave)

                for bot in wave:
                    bot.wave_id = wave_label
                    bot.login_reported = False
                    task = asyncio.create_task(bot.run())
                    self.tasks.append(task)
                    # slight stagger inside the wave to prevent simultaneous hits
                    await asyncio.sleep(0.5)

                if wave_index < waves - 1:
                    await asyncio.sleep(self.wave_delay)
            
            # Wait for all waves of this server to complete
            await self._wait_for_server_waves_complete(server_wave_labels, server)
            
            # Display server summary
            summary = self._get_server_summary(server)
            server_summaries[server] = summary
            self._display_server_summary(server, summary)
        
        # Display total summary
        if server_summaries:
            self._display_total_summary(server_summaries)

    def _init_wave(
        self,
        wave_id: str,
        server: str,
        wave_number: int,
        total_waves: int,
        bots: List[BotRuntime],
    ):
        self.wave_tracker[wave_id] = {
            "server": server,
            "wave_number": wave_number,
            "total_waves": total_waves,
            "total": len(bots),
            "success": 0,
            "failure": 0,
        }
        if wave_number == 1 and total_waves > 0:
            if self._wave_header_printed:
                self.log("")
            else:
                self._wave_header_printed = True
        self.log(f"[{server}] Wave {wave_number} - {len(bots)} account(s)")

    def _record_wave_result(
        self,
        bot: BotRuntime,
        *,
        success: bool,
        error: Optional[str] = None,
    ):
        wave_id = bot.wave_id
        name_hint = f" ({bot.account_name})" if bot.account_name else ""
        if success:
            line = f"- {bot.uid}{name_hint} logged in"
        else:
            reason = (error or "Unknown error").splitlines()[0]
            if len(reason) > 120:
                reason = reason[:117] + "..."
            line = f"- {bot.uid} failed: {reason}"
        self.log(line)

        if not wave_id or wave_id not in self.wave_tracker:
            return

        tracker = self.wave_tracker[wave_id]
        if success:
            tracker["success"] += 1
        else:
            tracker["failure"] += 1

        completed = tracker["success"] + tracker["failure"]
        if completed >= tracker["total"]:
            success_count = tracker["success"]
            total = tracker["total"]
            failure_count = tracker["failure"]
            summary = f"Total: {success_count}/{total} success"
            if failure_count:
                summary += f" ({failure_count} failed)"
            self.log(summary)
            self.log("")
            del self.wave_tracker[wave_id]
    
    async def _wait_for_server_waves_complete(self, wave_labels: List[str], server: str, timeout: float = 300.0):
        """Wait for all waves of a server to complete their login attempts."""
        start_time = time.monotonic()
        all_waves_complete = False
        
        # Wait for all waves to complete (removed from tracker)
        while not all_waves_complete:
            remaining_waves = [label for label in wave_labels if label in self.wave_tracker]
            if not remaining_waves:
                all_waves_complete = True
                break
            
            # Check timeout
            if time.monotonic() - start_time > timeout:
                self.log(f"⚠️ Warning: Timeout waiting for {server} waves to complete ({len(remaining_waves)} waves still pending)")
                break
            
            # Wait a bit before checking again
            await asyncio.sleep(2.0)
        
        # Give additional time for bots to fully connect and transition to online/idle state
        # This ensures accurate online counts in the summary
        await asyncio.sleep(8.0)
    
    def _get_server_summary(self, server: str) -> Dict[str, int]:
        """Get summary statistics for a specific server."""
        server_bots = self.bots_by_server.get(server, [])
        total = len(server_bots)
        # Count bots that are online (ONLINE, IDLE, BUSY, or IN_SQUAD)
        online = sum(1 for bot in server_bots if bot.status in {
            BotStatus.ONLINE, 
            BotStatus.IDLE, 
            BotStatus.BUSY, 
            BotStatus.IN_SQUAD
        })
        return {
            "total": total,
            "online": online,
        }
    
    def _display_server_summary(self, server: str, summary: Dict[str, int]):
        """Display summary for a specific server."""
        total = summary["total"]
        online = summary["online"]
        self.log("")
        self.log("=" * 60)
        self.log(f"{server} - {online} / {total} ID is online")
        self.log("=" * 60)
        self.log("")
    
    def _display_total_summary(self, server_summaries: Dict[str, Dict[str, int]]):
        """Display total summary across all servers."""
        total_online = sum(s["online"] for s in server_summaries.values())
        total_accounts = sum(s["total"] for s in server_summaries.values())
        
        self.log("")
        self.log("=" * 60)
        self.log("TOTAL ONLINE ID : " + str(total_online))
        self.log("=" * 60)
        self.log("")

    async def stop_all(self):
        self.shutdown_event.set()
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)

    async def on_bot_authenticated(self, bot: BotRuntime):
        async with self.lock:
            bot.status = BotStatus.ONLINE
            bot.last_error = None
            if not bot.login_reported:
                self._record_wave_result(bot, success=True)
                bot.login_reported = True

    async def on_bot_disconnected(self, bot: BotRuntime):
        async with self.lock:
            if not self.shutdown_event.is_set():
                bot.status = BotStatus.OFFLINE
                bot.busy_reason = None
                bot.busy_until = 0
                if bot.current_squad:
                    self.squad_registry.pop(bot.current_squad, None)
                    bot.current_squad = None
                to_remove = [key for key, value in self.owner_registry.items() if value is bot]
                for key in to_remove:
                    self.owner_registry.pop(key, None)
                # Clear session registry entry for this bot
                if bot.session_id:
                    self.session_registry.pop(bot.session_id, None)
                bot.owner_uid = None
                bot.squad_joined_time = None
                bot.session_id = None

    async def on_command_complete(self, bot: BotRuntime, action: Optional[str], success: bool):
        async with self.lock:
            if action == "join_squad":
                if success:
                    bot.status = BotStatus.IN_SQUAD
                    bot.busy_until = 0
                    bot.busy_reason = f"in_squad:{bot.current_squad}" if bot.current_squad else None
                else:
                    bot.status = BotStatus.IDLE
                    bot.busy_reason = None
                    bot.busy_until = 0
                    bot.current_squad = None
                    bot.squad_joined_time = None
            elif action == "leave_squad":
                bot.status = BotStatus.IDLE
                bot.busy_reason = None
                bot.busy_until = 0
                bot.current_squad = None
                bot.squad_joined_time = None
            else:
                if bot.status == BotStatus.BUSY or bot.status == BotStatus.IDLE:
                    if bot.command_queue.empty():
                        bot.status = BotStatus.IDLE
                        bot.busy_reason = None
                        bot.busy_until = 0
                    else:
                        bot.status = BotStatus.BUSY

    async def on_bot_login_failed(self, bot: BotRuntime, error: str):
        async with self.lock:
            bot.last_error = error
            if not bot.login_reported:
                self._record_wave_result(bot, success=False, error=error)
                bot.login_reported = True

    async def on_bot_joined_squad(
        self,
        bot: BotRuntime,
        team_code: str,
        owner_uid: Optional[str] = None,
    ):
        async with self.lock:
            normalized = self._normalize_team_code(team_code)
            if not normalized:
                return
            
            # Check if team_code is already taken by a different bot
            # This should not happen due to checks in assign_command, but handle it just in case
            existing = self.squad_registry.get(normalized)
            if existing and existing is not bot:
                # Another bot is already in this squad - this should not happen
                # Clear the old bot's registry entry
                self.log(f"⚠️ Warning: Team code {normalized} already has bot {existing.uid} (session: {existing.session_id}), clearing old bot")
                existing.current_squad = None
                existing.squad_joined_time = None
                # Clear session if bot was reassigned (only if it's not the same session)
                if existing.session_id and existing.session_id != bot.session_id:
                    # Only clear if different session - don't clear if same session (rejoin case)
                    old_session = self.session_registry.get(existing.session_id)
                    if old_session is existing:
                        # Only clear if this session still points to the old bot
                        self.session_registry.pop(existing.session_id, None)
                    existing.session_id = None
            
            # Clear bot's previous squad if it was in a different one
            if bot.current_squad and bot.current_squad != normalized:
                self.squad_registry.pop(bot.current_squad, None)
            
            # Register this bot in the squad
            bot.current_squad = normalized
            bot.squad_joined_time = datetime.now(UTC)
            self.squad_registry[normalized] = bot
            
            normalized_owner = self._normalize_owner_uid(owner_uid)
            if normalized_owner:
                # Update owner registry
                existing_owner_bot = self.owner_registry.get(normalized_owner)
                if existing_owner_bot and existing_owner_bot is not bot:
                    # Don't clear session here, just update owner registry
                    pass
                self.owner_registry[normalized_owner] = bot

    async def on_bot_left_squad(self, bot: BotRuntime):
        async with self.lock:
            if bot.current_squad:
                self.squad_registry.pop(bot.current_squad, None)
                bot.current_squad = None
            to_remove = [key for key, value in self.owner_registry.items() if value is bot]
            for key in to_remove:
                self.owner_registry.pop(key, None)
            # Don't clear session_id here - let the user keep control of the bot
            # Session will be cleared on disconnect or when bot is reassigned
            bot.owner_uid = None
            bot.squad_joined_time = None

    def _select_idle_bot(
        self, preferred_server: Optional[str] = None, *, allow_squad: bool = True
    ) -> Optional[BotRuntime]:
        """
        Select an idle bot that is available for assignment.
        If allow_squad=False, only select bots that are NOT in any squad.
        """
        candidates = [
            bot
            for bot in self.bots
            if bot.status == BotStatus.IDLE
            and bot.online_writer
            and (allow_squad or not bot.current_squad)  # If allow_squad=False, exclude bots in squads
        ]
        if preferred_server:
            candidates = [
                bot for bot in candidates if bot.server.lower() == preferred_server.lower()
            ]
        if not candidates:
            return None
        # Prefer bots that are not in any squad
        squad_free = [b for b in candidates if not b.current_squad]
        if squad_free:
            return min(squad_free, key=lambda b: b.index)
        return min(candidates, key=lambda b: b.index)

    def _resolve_squad_bot(
        self,
        team_code: Optional[str],
        owner_uid: Optional[str],
        preferred_server: Optional[str],
        session_id: Optional[str] = None,
    ) -> Optional[BotRuntime]:
        normalized_team = self._normalize_team_code(team_code)
        normalized_owner = self._normalize_owner_uid(owner_uid)

        # If session_id is provided, check if this session already owns a bot for this squad/owner
        if session_id:
            existing_bot = self.session_registry.get(session_id)
            if existing_bot and existing_bot.online_writer:
                # Verify it matches the requested squad/owner and server
                if normalized_team and existing_bot.current_squad == normalized_team:
                    if not preferred_server or existing_bot.server.lower() == preferred_server.lower():
                        return existing_bot
                if normalized_owner and existing_bot.owner_uid == normalized_owner:
                    if not preferred_server or existing_bot.server.lower() == preferred_server.lower():
                        return existing_bot

        if normalized_team:
            bound = self.squad_registry.get(normalized_team)
            if self._bot_is_available(bound, preferred_server):
                # Verify session ownership if session_id is provided
                if session_id:
                    if bound.session_id and bound.session_id != session_id:
                        # Bot is controlled by different session
                        return None
                return bound

        if normalized_owner:
            bound = self.owner_registry.get(normalized_owner)
            if self._bot_is_available(bound, preferred_server):
                # Verify session ownership if session_id is provided
                if session_id:
                    if bound.session_id and bound.session_id != session_id:
                        # Bot is controlled by different session
                        return None
                return bound

        fallback = self._select_squad_bot(normalized_team, preferred_server)
        if fallback:
            # Verify session ownership if session_id is provided
            if session_id:
                if fallback.session_id and fallback.session_id != session_id:
                    return None
            return fallback

        if normalized_owner:
            bound = self.owner_registry.get(normalized_owner)
            if bound and bound.online_writer:
                # Verify session ownership if session_id is provided
                if session_id:
                    if bound.session_id and bound.session_id != session_id:
                        return None
                return bound

        return None

    def _select_squad_bot(
        self,
        team_code: Optional[str] = None,
        preferred_server: Optional[str] = None,
    ) -> Optional[BotRuntime]:
        normalized = self._normalize_team_code(team_code)
        if normalized:
            bound = self.squad_registry.get(normalized)
            if bound and bound.online_writer:
                if not preferred_server or bound.server.lower() == preferred_server.lower():
                    return bound
        candidates = [
            bot
            for bot in self.bots
            if bot.online_writer
            and bot.current_squad
            and (
                team_code is None
                or str(bot.current_squad).lower() == str(team_code).lower()
            )
        ]
        if preferred_server:
            candidates = [
                bot for bot in candidates if bot.server.lower() == preferred_server.lower()
            ]
        if not candidates:
            return None
        return min(candidates, key=lambda b: b.index)

    async def assign_command(self, action: str, payload: Dict) -> Optional[BotRuntime]:
        async with self.lock:
            self._refresh_busy_states()
            preferred_server = payload.get("preferred_server")
            session_id = payload.get("session_id")
            team_code = self._extract_team_code(payload)
            if team_code:
                payload = dict(payload)
                payload["team_code"] = team_code
            owner_uid = self._extract_owner_uid(payload)
            if owner_uid and payload.get("main_uid") != owner_uid:
                payload = dict(payload)
                payload["main_uid"] = owner_uid
            
            if action == "leave_squad":
                # For leave_squad, must verify session ownership
                bot = self._resolve_squad_bot(team_code, owner_uid, preferred_server, session_id)
                if not bot:
                    # Try to find bot by session_id only
                    if session_id:
                        bot = self.session_registry.get(session_id)
                        if bot and not bot.online_writer:
                            bot = None
                    # If still not found, return None (user doesn't own this bot)
                    if not bot:
                        return None
                # Verify the bot belongs to this session
                if session_id and bot.session_id and bot.session_id != session_id:
                    return None
            elif action == "freestyle_emote":
                if not team_code:
                    return None
                bot = self._select_idle_bot(preferred_server, allow_squad=False)
                if not bot or bot.current_squad:
                    return None
                if session_id:
                    if bot.session_id and bot.session_id != session_id:
                        return None
                    bot.session_id = session_id
                    self.session_registry[session_id] = bot
            elif action in {"emote", "emote_batch"}:
                # For emote commands, must verify session ownership
                bot = self._resolve_squad_bot(team_code, owner_uid, preferred_server, session_id)
                if not bot:
                    return None
                # Verify the bot belongs to this session
                if session_id and bot.session_id and bot.session_id != session_id:
                    return None
            elif action == "join_squad":
                # For join_squad, check if team_code is already taken
                if not team_code:
                    return None
                normalized_team = self._normalize_team_code(team_code)
                if not normalized_team:
                    return None
                
                # Check if team_code is already taken
                existing_bot = self.squad_registry.get(normalized_team)
                if existing_bot:
                    # Team code is taken - check if it's by the same session
                    if session_id and existing_bot.session_id == session_id:
                        # Same session trying to rejoin - allow it (same bot)
                        bot = existing_bot
                    else:
                        # Team code is taken by a different session/bot - reject
                        return None
                else:
                    # Team code is available - assign a new idle bot
                    # IMPORTANT: Only select bots that are NOT already in any squad
                    bot = self._select_idle_bot(preferred_server, allow_squad=False)
                    if not bot:
                        return None
                    # Verify bot is not already in a squad
                    if bot.current_squad:
                        return None
                    # Set session_id when assigning bot
                    if session_id:
                        # If bot already has a different session, reject
                        if bot.session_id and bot.session_id != session_id:
                            return None
                        bot.session_id = session_id
                        self.session_registry[session_id] = bot
            else:
                # For quick_invite, assign to idle bot and set session
                bot = self._select_idle_bot(preferred_server, allow_squad=True)
                if not bot:
                    return None
                # Set session_id when assigning bot
                if session_id:
                    # If bot already has a different session, reject
                    if bot.session_id and bot.session_id != session_id:
                        return None
                    bot.session_id = session_id
                    self.session_registry[session_id] = bot

            if not bot:
                return None

            bot.status = BotStatus.BUSY
            bot.busy_reason = action
            command = dict(payload)
            command["action"] = action
            await bot.command_queue.put(command)
            return bot

    def get_status_summary(self) -> Dict:
        summary = {
            "total": len(self.bots),
            "online": sum(1 for bot in self.bots if bot.status in {BotStatus.IDLE, BotStatus.BUSY, BotStatus.IN_SQUAD}),
            "idle": sum(1 for bot in self.bots if bot.status == BotStatus.IDLE),
            "busy": sum(1 for bot in self.bots if bot.status == BotStatus.BUSY),
            "in_squad": sum(1 for bot in self.bots if bot.status == BotStatus.IN_SQUAD),
            "error": sum(1 for bot in self.bots if bot.status == BotStatus.ERROR),
        }
        per_server: Dict[str, Dict[str, int]] = {}
        for bot in self.bots:
            per_server.setdefault(bot.server, {"total": 0, "online": 0, "idle": 0, "busy": 0, "in_squad": 0})
            bucket = per_server[bot.server]
            bucket["total"] += 1
            if bot.status in {BotStatus.IDLE, BotStatus.BUSY, BotStatus.IN_SQUAD}:
                bucket["online"] += 1
            if bot.status == BotStatus.IDLE:
                bucket["idle"] += 1
            if bot.status == BotStatus.BUSY:
                bucket["busy"] += 1
            if bot.status == BotStatus.IN_SQUAD:
                bucket["in_squad"] += 1
        summary["servers"] = per_server
        return summary

    def get_bot_details(self) -> List[Dict]:
        details = []
        for bot in self.bots:
            details.append(
                {
                    "uid": bot.uid,
                    "server": bot.server,
                    "status": bot.status.value,
                    "account_name": bot.account_name,
                    "busy_reason": bot.busy_reason,
                    "last_error": bot.last_error,
                    "current_squad": bot.current_squad,
                    "last_activity": bot.last_activity.isoformat() if bot.last_activity else None,
                }
            )
        return details


# ---------------------------------------------------------------------------
# Web API
# ---------------------------------------------------------------------------


def create_web_app(controller: MultiBotController) -> web.Application:
    app = web.Application()

    async def status_handler(_: web.Request):
        return web.json_response(controller.get_status_summary())

    async def bots_handler(_: web.Request):
        return web.json_response({"bots": controller.get_bot_details()})

    async def command_handler(request: web.Request):
        try:
            payload = await request.json()
        except Exception:
            return web.json_response({"status": "error", "message": "Invalid JSON payload"}, status=400)

        action = payload.get("action")
        if not action:
            return web.json_response({"status": "error", "message": "Missing action"}, status=400)

        bot = await controller.assign_command(action, payload)
        if not bot:
            session_id = payload.get("session_id")
            preferred_server = payload.get("preferred_server")
            # Provide more specific error messages
            if action in {"leave_squad", "emote", "emote_batch"}:
                error_msg = "No bot found for this squad/owner"
                if session_id:
                    error_msg += " that belongs to your session"
                if preferred_server:
                    error_msg += f" on {preferred_server} server"
                return web.json_response(
                    {"status": "error", "message": error_msg},
                    status=503,
                )
            elif action == "freestyle_emote":
                error_msg = "Cannot perform freestyle emote"
                team_code = payload.get("team_code")
                if team_code:
                    error_msg += f" for squad '{team_code}'"
                if preferred_server:
                    error_msg += f" - No available idle bot on {preferred_server} server"
                else:
                    error_msg += " - No available idle bot"
                return web.json_response(
                    {"status": "error", "message": error_msg},
                    status=503,
                )
            elif action == "join_squad":
                error_msg = "Cannot join squad"
                team_code = payload.get("team_code")
                if team_code:
                    error_msg += f" '{team_code}'"
                    # Check if team code is already taken
                    normalized = MultiBotController._normalize_team_code(team_code)
                    if normalized and normalized in controller.squad_registry:
                        existing_bot = controller.squad_registry[normalized]
                        existing_session = existing_bot.session_id if existing_bot else None
                        request_session = payload.get("session_id")
                        if existing_session and existing_session != request_session:
                            error_msg = f"Team code '{team_code}' is already taken by another user's bot"
                        else:
                            error_msg = f"Team code '{team_code}' is already in use"
                    elif preferred_server:
                        error_msg += f" - No available idle bot on {preferred_server} server (all bots may be in squads)"
                    else:
                        error_msg += " - No available idle bot (all bots may be in squads)"
                else:
                    if preferred_server:
                        error_msg += f" - No available idle bot on {preferred_server} server"
                    else:
                        error_msg += " - No available idle bot"
                return web.json_response(
                    {"status": "error", "message": error_msg},
                    status=503,
                )
            else:
                error_msg = "No available bot"
                if preferred_server:
                    error_msg += f" on {preferred_server} server"
                error_msg += " for this action right now"
                return web.json_response(
                    {"status": "error", "message": error_msg},
                    status=503,
                )

        return web.json_response(
            {
                "status": "ok",
                "message": f"Command '{action}' assigned to bot {bot.account_name or bot.uid}",
                "bot": {"uid": bot.uid, "server": bot.server, "status": bot.status.value},
            }
        )

    app.router.add_get("/status", status_handler)
    app.router.add_get("/bots", bots_handler)
    app.router.add_post("/command", command_handler)
    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main():
    controller = MultiBotController()
    await controller.load_accounts()

    if not controller.bots:
        print("❌ No bot accounts loaded. Please check config JSON files.")
        return

    banner = render("Byte Force", colors=["white", "red"], align="center")
    print(banner)
    print(f"🚀 Starting multi-bot system with {len(controller.bots)} accounts...")

    await controller.start_all()

    app = create_web_app(controller)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 8080)
    await site.start()
    print("🌐 Internal API server started at http://127.0.0.1:8080")

    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        raise
    except KeyboardInterrupt:
        print("\n🛑 Shutting down multi-bot system...")
    finally:
        await controller.stop_all()
        await runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Bot system stopped by user.")

