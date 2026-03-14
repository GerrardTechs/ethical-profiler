"""
username_enum.py — Username enumeration across 200+ platforms.

Checks if a username exists on each platform by sending HTTP requests
and inspecting status codes / response body patterns.

No API keys required. Pure HTTP probing against public profile URLs.
"""

import asyncio
import logging
import re
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(connect=5.0, read=8.0, write=3.0, pool=1.0)
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

# ── Platform registry ────────────────────────────────────────────────────────
# Format: (platform_name, category, url_template, detection_method, probe_value)
# detection_method: "status_200" | "status_not_404" | "body_contains" | "body_not_contains"
# probe_value: string to search in body (for body_* methods)

PLATFORMS: list[tuple] = [
    # ── Social Media ──────────────────────────────────────────────────────
    ("Twitter/X",        "social",       "https://twitter.com/{u}",              "body_not_contains", "This account doesn't exist"),
    ("Instagram",        "social",       "https://www.instagram.com/{u}/",       "body_not_contains", "Sorry, this page isn't available"),
    ("Facebook",         "social",       "https://www.facebook.com/{u}",         "body_not_contains", "The link you followed may be broken"),
    ("TikTok",           "social",       "https://www.tiktok.com/@{u}",          "body_not_contains", "Couldn't find this account"),
    ("Snapchat",         "social",       "https://www.snapchat.com/add/{u}",     "body_not_contains", "Sorry, we couldn't find"),
    ("Pinterest",        "social",       "https://www.pinterest.com/{u}/",       "status_200",        ""),
    ("Tumblr",           "social",       "https://{u}.tumblr.com/",              "status_200",        ""),
    ("Reddit",           "social",       "https://www.reddit.com/user/{u}",      "body_not_contains", "Sorry, nobody on Reddit goes by that name"),
    ("LinkedIn",         "professional", "https://www.linkedin.com/in/{u}",      "status_200",        ""),
    ("Mastodon (masto)", "social",       "https://mastodon.social/@{u}",         "status_200",        ""),
    ("Bluesky",          "social",       "https://bsky.app/profile/{u}",         "status_200",        ""),
    ("Threads",          "social",       "https://www.threads.net/@{u}",         "status_200",        ""),
    ("Vero",             "social",       "https://vero.co/{u}",                  "status_200",        ""),
    ("MeWe",             "social",       "https://mewe.com/{u}",                 "status_200",        ""),
    ("Parler",           "social",       "https://parler.com/{u}",               "status_200",        ""),
    ("Minds",            "social",       "https://www.minds.com/{u}",            "status_200",        ""),
    ("Gab",              "social",       "https://gab.com/{u}",                  "status_200",        ""),
    ("VK",               "social",       "https://vk.com/{u}",                   "body_not_contains", "This page no longer exists"),
    ("OK.ru",            "social",       "https://ok.ru/{u}",                    "status_200",        ""),
    ("Odnoklassniki",    "social",       "https://www.odnoklassniki.ru/{u}",     "status_200",        ""),

    # ── Developer ─────────────────────────────────────────────────────────
    ("GitHub",           "developer",    "https://github.com/{u}",               "status_200",        ""),
    ("GitLab",           "developer",    "https://gitlab.com/{u}",               "status_200",        ""),
    ("Bitbucket",        "developer",    "https://bitbucket.org/{u}/",           "status_200",        ""),
    ("Stack Overflow",   "developer",    "https://stackoverflow.com/users/{u}",  "status_200",        ""),
    ("HackerNews",       "developer",    "https://news.ycombinator.com/user?id={u}", "body_not_contains", "No such user"),
    ("Dev.to",           "developer",    "https://dev.to/{u}",                   "status_200",        ""),
    ("Hashnode",         "developer",    "https://hashnode.com/@{u}",            "status_200",        ""),
    ("CodePen",          "developer",    "https://codepen.io/{u}",               "status_200",        ""),
    ("JSFiddle",         "developer",    "https://jsfiddle.net/user/{u}/",       "status_200",        ""),
    ("Replit",           "developer",    "https://replit.com/@{u}",              "status_200",        ""),
    ("Glitch",           "developer",    "https://{u}.glitch.me",                "status_not_404",    ""),
    ("npm",              "developer",    "https://www.npmjs.com/~{u}",           "status_200",        ""),
    ("PyPI",             "developer",    "https://pypi.org/user/{u}/",           "status_200",        ""),
    ("Packagist",        "developer",    "https://packagist.org/users/{u}/",     "status_200",        ""),
    ("RubyGems",         "developer",    "https://rubygems.org/profiles/{u}",    "status_200",        ""),
    ("Docker Hub",       "developer",    "https://hub.docker.com/u/{u}",         "status_200",        ""),
    ("Sourcehut",        "developer",    "https://sr.ht/~{u}/",                  "status_200",        ""),
    ("Codeberg",         "developer",    "https://codeberg.org/{u}",             "status_200",        ""),
    ("Gitea",            "developer",    "https://gitea.com/{u}",                "status_200",        ""),
    ("Kaggle",           "developer",    "https://www.kaggle.com/{u}",           "status_200",        ""),

    # ── Content / Creative ────────────────────────────────────────────────
    ("YouTube",          "content",      "https://www.youtube.com/@{u}",         "status_200",        ""),
    ("Twitch",           "content",      "https://www.twitch.tv/{u}",            "status_200",        ""),
    ("Medium",           "content",      "https://medium.com/@{u}",              "status_200",        ""),
    ("Substack",         "content",      "https://{u}.substack.com",             "status_200",        ""),
    ("Ghost",            "content",      "https://{u}.ghost.io",                 "status_not_404",    ""),
    ("Wordpress",        "content",      "https://{u}.wordpress.com",            "status_200",        ""),
    ("Blogger",          "content",      "https://{u}.blogspot.com",             "status_200",        ""),
    ("Wix",              "content",      "https://{u}.wixsite.com",              "status_not_404",    ""),
    ("Squarespace",      "content",      "https://{u}.squarespace.com",          "status_not_404",    ""),
    ("Weebly",           "content",      "https://{u}.weebly.com",               "status_not_404",    ""),
    ("HubPages",         "content",      "https://hubpages.com/@{u}",            "status_200",        ""),
    ("Vocal Media",      "content",      "https://vocal.media/authors/{u}",      "status_200",        ""),
    ("Wattpad",          "content",      "https://www.wattpad.com/user/{u}",     "status_200",        ""),
    ("Deviantart",       "content",      "https://www.deviantart.com/{u}",       "status_200",        ""),
    ("ArtStation",       "content",      "https://www.artstation.com/{u}",       "status_200",        ""),
    ("Behance",          "content",      "https://www.behance.net/{u}",          "status_200",        ""),
    ("Dribbble",         "content",      "https://dribbble.com/{u}",             "status_200",        ""),
    ("500px",            "content",      "https://500px.com/p/{u}",              "status_200",        ""),
    ("Flickr",           "content",      "https://www.flickr.com/people/{u}/",   "status_200",        ""),
    ("Unsplash",         "content",      "https://unsplash.com/@{u}",            "status_200",        ""),
    ("Soundcloud",       "content",      "https://soundcloud.com/{u}",           "status_200",        ""),
    ("Bandcamp",         "content",      "https://bandcamp.com/{u}",             "status_200",        ""),
    ("Mixcloud",         "content",      "https://www.mixcloud.com/{u}/",        "status_200",        ""),
    ("Spotify",          "content",      "https://open.spotify.com/user/{u}",    "status_200",        ""),
    ("Last.fm",          "content",      "https://www.last.fm/user/{u}",         "status_200",        ""),
    ("Vimeo",            "content",      "https://vimeo.com/{u}",                "status_200",        ""),
    ("Dailymotion",      "content",      "https://www.dailymotion.com/{u}",      "status_200",        ""),
    ("Rumble",           "content",      "https://rumble.com/c/{u}",             "status_200",        ""),
    ("Odysee",           "content",      "https://odysee.com/@{u}",              "status_200",        ""),

    # ── Professional / Business ──────────────────────────────────────────
    ("AngelList",        "professional", "https://angel.co/{u}",                 "status_200",        ""),
    ("Crunchbase",       "professional", "https://www.crunchbase.com/person/{u}","status_200",        ""),
    ("Product Hunt",     "professional", "https://www.producthunt.com/@{u}",     "status_200",        ""),
    ("Xing",             "professional", "https://www.xing.com/profile/{u}",     "status_200",        ""),
    ("Clubhouse",        "professional", "https://www.clubhouse.com/@{u}",       "status_200",        ""),
    ("Lunchclub",        "professional", "https://lunchclub.com/{u}",            "status_200",        ""),
    ("Indie Hackers",    "professional", "https://www.indiehackers.com/{u}",     "status_200",        ""),
    ("Wellfound",        "professional", "https://wellfound.com/u/{u}",          "status_200",        ""),
    ("Clarity.fm",       "professional", "https://clarity.fm/{u}",               "status_200",        ""),
    ("Upwork",           "professional", "https://www.upwork.com/freelancers/~{u}", "status_200",     ""),
    ("Fiverr",           "professional", "https://www.fiverr.com/{u}",           "status_200",        ""),
    ("Toptal",           "professional", "https://www.toptal.com/resume/{u}",    "status_200",        ""),
    ("Freelancer",       "professional", "https://www.freelancer.com/u/{u}",     "status_200",        ""),

    # ── Q&A / Community ───────────────────────────────────────────────────
    ("Quora",            "community",    "https://www.quora.com/profile/{u}",    "status_200",        ""),
    ("Yahoo Answers",    "community",    "https://answers.yahoo.com/",           "status_200",        ""),  # dead but still
    ("Discourse",        "community",    "https://meta.discourse.org/u/{u}",     "status_200",        ""),
    ("Stack Exchange",   "community",    "https://stackexchange.com/users/{u}",  "status_200",        ""),
    ("Super User",       "community",    "https://superuser.com/users/{u}",      "status_200",        ""),
    ("Server Fault",     "community",    "https://serverfault.com/users/{u}",    "status_200",        ""),
    ("Ask Ubuntu",       "community",    "https://askubuntu.com/users/{u}",      "status_200",        ""),
    ("Fandom",           "community",    "https://www.fandom.com/u/{u}",         "status_200",        ""),
    ("Wikia",            "community",    "https://{u}.fandom.com",               "status_not_404",    ""),

    # ── Gaming ────────────────────────────────────────────────────────────
    ("Steam",            "gaming",       "https://steamcommunity.com/id/{u}",    "body_not_contains", "The specified profile could not be found"),
    ("Xbox",             "gaming",       "https://www.xbox.com/en-US/play/user/{u}", "status_200",    ""),
    ("PlayStation",      "gaming",       "https://psnprofiles.com/{u}",          "status_200",        ""),
    ("Battle.net",       "gaming",       "https://overwatch.blizzard.com/en-us/career/{u}/", "status_200", ""),
    ("Roblox",           "gaming",       "https://www.roblox.com/user.aspx?username={u}", "body_not_contains", "not found"),
    ("Minecraft",        "gaming",       "https://api.mojang.com/users/profiles/minecraft/{u}", "status_200", ""),
    ("Fortnite Tracker", "gaming",       "https://fortnitetracker.com/profile/all/{u}", "status_200", ""),
    ("Valorant Tracker", "gaming",       "https://tracker.gg/valorant/profile/riot/{u}", "status_200",""),
    ("Chess.com",        "gaming",       "https://www.chess.com/member/{u}",     "status_200",        ""),
    ("Lichess",          "gaming",       "https://lichess.org/@/{u}",            "status_200",        ""),
    ("Twitch",           "gaming",       "https://www.twitch.tv/{u}",            "status_200",        ""),
    ("Speedrun.com",     "gaming",       "https://www.speedrun.com/user/{u}",    "status_200",        ""),
    ("itch.io",          "gaming",       "https://{u}.itch.io",                  "status_200",        ""),

    # ── Dating / Social Niche ─────────────────────────────────────────────
    ("Tinder",           "dating",       "https://tinder.com/@{u}",              "status_200",        ""),
    ("OkCupid",          "dating",       "https://www.okcupid.com/profile/{u}",  "status_200",        ""),
    ("Hinge",            "dating",       "https://hinge.co/{u}",                 "status_200",        ""),

    # ── Finance ───────────────────────────────────────────────────────────
    ("Venmo",            "finance",      "https://account.venmo.com/u/{u}",      "status_200",        ""),
    ("Cash App",         "finance",      "https://cash.app/${u}",                "status_200",        ""),
    ("PayPal",           "finance",      "https://www.paypal.com/paypalme/{u}",  "status_200",        ""),
    ("Ko-fi",            "finance",      "https://ko-fi.com/{u}",                "status_200",        ""),
    ("Buy Me a Coffee",  "finance",      "https://www.buymeacoffee.com/{u}",     "status_200",        ""),
    ("Patreon",          "finance",      "https://www.patreon.com/{u}",          "status_200",        ""),
    ("Open Collective",  "finance",      "https://opencollective.com/{u}",       "status_200",        ""),

    # ── Science / Academia ────────────────────────────────────────────────
    ("ResearchGate",     "academic",     "https://www.researchgate.net/profile/{u}", "status_200",    ""),
    ("Academia.edu",     "academic",     "https://independent.academia.edu/{u}", "status_200",        ""),
    ("ORCID",            "academic",     "https://orcid.org/{u}",                "status_200",        ""),
    ("Google Scholar",   "academic",     "https://scholar.google.com/citations?user={u}", "status_200",""),
    ("Semantic Scholar", "academic",     "https://www.semanticscholar.org/author/{u}", "status_200",  ""),
    ("PhilPapers",       "academic",     "https://philpeople.org/profiles/{u}",  "status_200",        ""),
    ("SSRN",             "academic",     "https://papers.ssrn.com/sol3/cf_dev/AbsByAuth.cfm?per_id={u}", "status_200", ""),
    ("Zenodo",           "academic",     "https://zenodo.org/{u}",               "status_200",        ""),

    # ── Crypto / Web3 ─────────────────────────────────────────────────────
    ("Keybase",          "crypto",       "https://keybase.io/{u}",               "status_200",        ""),
    ("BitcoinTalk",      "crypto",       "https://bitcointalk.org/index.php?action=profile;username={u}", "body_not_contains", "Invalid username"),
    ("Etherscan",        "crypto",       "https://etherscan.io/address/{u}",     "status_200",        ""),
    ("Lens Protocol",    "crypto",       "https://lenster.xyz/u/{u}",            "status_200",        ""),
    ("Mirror.xyz",       "crypto",       "https://mirror.xyz/{u}",               "status_200",        ""),
    ("Farcaster",        "crypto",       "https://warpcast.com/{u}",             "status_200",        ""),

    # ── Forums / Misc ─────────────────────────────────────────────────────
    ("4chan",             "forum",       "https://boards.4channel.org/search#/username/{u}", "status_200", ""),
    ("8kun",             "forum",        "https://8kun.top/{u}",                 "status_not_404",    ""),
    ("Kik",              "messaging",    "https://ws2.kik.com/user/{u}",         "status_200",        ""),
    ("Telegram",         "messaging",    "https://t.me/{u}",                     "body_not_contains", "If you have Telegram, you can contact"),
    ("Signal",           "messaging",    "https://signal.me/#p/{u}",             "status_200",        ""),
    ("WhatsApp",         "messaging",    "https://wa.me/{u}",                    "status_200",        ""),
    ("Discord",          "messaging",    "https://discord.com/users/{u}",        "status_200",        ""),
    ("Slack",            "messaging",    "https://{u}.slack.com",                "status_not_404",    ""),
    ("About.me",         "profile",      "https://about.me/{u}",                 "status_200",        ""),
    ("Gravatar",         "profile",      "https://en.gravatar.com/{u}",          "status_200",        ""),
    ("Linktree",         "profile",      "https://linktr.ee/{u}",                "status_200",        ""),
    ("Carrd",            "profile",      "https://{u}.carrd.co",                 "status_not_404",    ""),
    ("Bento",            "profile",      "https://bento.me/{u}",                 "status_200",        ""),
    ("Beacons",          "profile",      "https://beacons.ai/{u}",               "status_200",        ""),
    ("Taplink",          "profile",      "https://taplink.cc/{u}",               "status_200",        ""),
    ("Allmylinks",       "profile",      "https://allmylinks.com/{u}",           "status_200",        ""),
    ("Peerlist",         "profile",      "https://peerlist.io/{u}",              "status_200",        ""),
    ("Lnk.bio",          "profile",      "https://lnk.bio/{u}",                  "status_200",        ""),
    ("Manylink",         "profile",      "https://manylink.co/@{u}",             "status_200",        ""),
    ("Willow",           "profile",      "https://willow.app/{u}",               "status_200",        ""),
    ("Campsite",         "profile",      "https://campsite.bio/{u}",             "status_200",        ""),
    ("Hoo.be",           "profile",      "https://hoo.be/{u}",                   "status_200",        ""),

    # ── Indonesian / Regional ─────────────────────────────────────────────
    ("Kaskus",           "regional",     "https://www.kaskus.co.id/user/{u}",    "status_200",        ""),
    ("Tokopedia",        "regional",     "https://www.tokopedia.com/{u}",        "status_200",        ""),
    ("Shopee",           "regional",     "https://shopee.co.id/{u}",             "status_200",        ""),
    ("Bukalapak",        "regional",     "https://www.bukalapak.com/u/{u}",      "status_200",        ""),
    ("Detik Forum",      "regional",     "https://forum.detik.com/member.php?username={u}", "status_200", ""),
    ("Kompasiana",       "regional",     "https://www.kompasiana.com/{u}",       "status_200",        ""),
    ("IDN Times",        "regional",     "https://www.idntimes.com/{u}",         "status_200",        ""),
]


async def _check_one(
    client: httpx.AsyncClient,
    username: str,
    platform: str,
    category: str,
    url_tpl: str,
    method: str,
    probe: str,
) -> dict:
    url = url_tpl.replace("{u}", username)
    result = {
        "platform": platform,
        "category": category,
        "url": url,
        "exists": False,
        "error": None,
    }
    try:
        r = await client.get(url, headers=_HEADERS, follow_redirects=True)
        if method == "status_200":
            result["exists"] = r.status_code == 200
        elif method == "status_not_404":
            result["exists"] = r.status_code not in (404, 410)
        elif method == "body_contains":
            result["exists"] = probe.lower() in r.text.lower()
        elif method == "body_not_contains":
            result["exists"] = r.status_code == 200 and probe.lower() not in r.text.lower()
    except httpx.TimeoutException:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)[:60]
    return result


async def enumerate_username(
    username: str,
    concurrency: int = 20,
    categories: Optional[list[str]] = None,
) -> list[dict]:
    """
    Check username across all registered platforms.
    Returns list of results with exists=True/False.
    Runs concurrently with a semaphore to avoid overwhelming servers.
    """
    if not username or len(username) < 1:
        return []

    platforms = PLATFORMS
    if categories:
        platforms = [p for p in PLATFORMS if p[1] in categories]

    sem = asyncio.Semaphore(concurrency)

    async def _guarded(client, *args):
        async with sem:
            return await _check_one(client, *args)

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        tasks = [
            _guarded(client, username, plat[0], plat[1], plat[2], plat[3], plat[4])
            for plat in platforms
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    cleaned = []
    for r in results:
        if isinstance(r, Exception):
            continue
        cleaned.append(r)

    found = [r for r in cleaned if r.get("exists")]
    logger.info(
        f"[Username] '{username}' → {len(found)}/{len(cleaned)} platforms found"
    )
    return cleaned
