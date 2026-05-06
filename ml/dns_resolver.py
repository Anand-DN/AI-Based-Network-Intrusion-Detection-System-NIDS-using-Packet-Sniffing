import socket
import threading
import time
from collections import OrderedDict

KNOWN_HOSTS = {
    "1e100.net": "Google",
    "googlevideo.com": "YouTube",
    "ytimg.com": "YouTube",
    "google.com": "Google",
    "googleusercontent.com": "Google",
    "gstatic.com": "Google",
    "googleapis.com": "Google API",
    "youtube.com": "YouTube",
    "akamai": "Akamai CDN",
    "akamaiedge": "Akamai CDN",
    "cloudflare": "Cloudflare",
    "cdn.cloudflare.net": "Cloudflare",
    "facebook.com": "Facebook",
    "fbcdn.net": "Facebook",
    "instagram.com": "Instagram",
    "whatsapp.net": "WhatsApp",
    "amazonaws.com": "AWS",
    "amazon.com": "Amazon",
    "awsstatic.com": "AWS",
    "microsoft.com": "Microsoft",
    "azure.com": "Microsoft Azure",
    "windows.net": "Microsoft",
    "live.com": "Microsoft",
    "outlook.com": "Microsoft",
    "xboxlive.com": "Xbox",
    "netflix.com": "Netflix",
    "nflxvideo.net": "Netflix",
    "nflxso.net": "Netflix",
    "twitch.tv": "Twitch",
    "spotify.com": "Spotify",
    "spotifycdn.com": "Spotify",
    "discord.com": "Discord",
    "discordapp.net": "Discord",
    "github.com": "GitHub",
    "github.io": "GitHub Pages",
    "githubusercontent.com": "GitHub",
    "twitter.com": "X/Twitter",
    "x.com": "X/Twitter",
    "twimg.com": "X/Twitter",
    "tiktokv.com": "TikTok",
    "tiktokcdn.com": "TikTok",
    "apple.com": "Apple",
    "icloud.com": "Apple iCloud",
    "apple-dns.net": "Apple",
    "yahoo.com": "Yahoo",
    "yahooapis.com": "Yahoo",
    "fastly": "Fastly CDN",
    "edgecastcdn": "Edgecast CDN",
    "zoom.us": "Zoom",
    "slack.com": "Slack",
    "whatsapp.com": "WhatsApp",
    "snapchat.com": "Snapchat",
    "reddit.com": "Reddit",
    "pinterest.com": "Pinterest",
    "linkedin.com": "LinkedIn",
    "roblox.com": "Roblox",
    "robloxcdn.com": "Roblox",
    "minecraft.net": "Minecraft",
    "mojang.com": "Minecraft",
    "epicgames.com": "Epic Games",
    "steamcontent.com": "Steam",
    "steamcdn": "Steam",
    "steampowered.com": "Steam",
}

class DNSResolver:
    def __init__(self, max_size=500, ttl=300):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl
        self.pending = set()
        self._lock = threading.Lock()

    @staticmethod
    def _get_friendly_name(hostname):
        if not hostname:
            return hostname
        hostname_lower = hostname.lower()
        for pattern, friendly in KNOWN_HOSTS.items():
            if pattern in hostname_lower:
                return friendly
        return hostname.split('.')[0].capitalize() if '.' in hostname else hostname

    def resolve(self, ip):
        with self._lock:
            if ip in self.cache:
                entry = self.cache[ip]
                if time.time() - entry["time"] < self.ttl:
                    self.cache.move_to_end(ip)
                    return entry["name"]
                else:
                    del self.cache[ip]
        if ip in self.pending:
            return None
        self.pending.add(ip)
        t = threading.Thread(target=self._resolve_async, args=(ip,), daemon=True)
        t.start()
        return None

    def _resolve_async(self, ip):
        try:
            raw_name = socket.gethostbyaddr(ip)[0]
            friendly = self._get_friendly_name(raw_name)
            with self._lock:
                self.cache[ip] = {"name": friendly, "raw": raw_name, "time": time.time()}
                if len(self.cache) > self.max_size:
                    self.cache.popitem(last=False)
        except (socket.herror, socket.gaierror, OSError):
            pass
        finally:
            self.pending.discard(ip)

    def get(self, ip):
        with self._lock:
            if ip in self.cache:
                return self.cache[ip]["name"]
        result = self.resolve(ip)
        return result or ip

    def resolve_all(self, ip_list):
        for ip in ip_list:
            self.resolve(ip)

    def clear(self):
        with self._lock:
            self.cache.clear()
            self.pending.clear()

    def get_stats(self):
        with self._lock:
            return {"cached": len(self.cache), "pending": len(self.pending)}
