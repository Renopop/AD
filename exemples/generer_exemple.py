#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Génère un fichier querylog.json fictif (même format que celui d'AdGuard Home) pour
tester l'outil sans toucher au vrai journal.

    python3 exemples/generer_exemple.py exemples/querylog.json [--jours 14]

Appareils simulés :
  192.168.1.42  iPhone (indices iOS + Snapchat/TikTok) avec des consultations de sites
                sensibles surtout la nuit (22h-1h) et le week-end.
  192.168.1.20  PC Windows sans activité sensible.
  192.168.1.31  Android avec une appli de rencontres le midi.
"""
import argparse
import datetime as dt
import json
import random

TZ = dt.timezone(dt.timedelta(hours=2))

NORMAL = ["gateway.icloud.com", "time-ios.apple.com", "gsp-ssl.ls.apple.com", "api.snapchat.com",
          "app.snapchat.com", "sc-cdn.net", "api16-normal-c-useast1a.tiktokv.com", "v16-webapp.tiktok.com",
          "i.instagram.com", "graph.instagram.com", "www.google.com", "youtubei.googleapis.com",
          "rr1---sn-25glenl6.googlevideo.com", "discord.com", "gateway.discord.gg", "www.wikipedia.org",
          "cdn.jsdelivr.net", "fonts.gstatic.com", "mask.icloud.com"]
PC = ["www.msftconnecttest.com", "download.windowsupdate.com", "www.google.fr", "www.youtube.com",
      "steamcommunity.com", "cdn.cloudflare.steamstatic.com", "www.amazon.fr", "outlook.live.com"]
ANDROID = ["connectivitycheck.gstatic.com", "mtalk.google.com", "play.googleapis.com", "www.google.com",
           "api.whatsapp.com", "graph.facebook.com", "www.leboncoin.fr"]

PORN = [("fr.pornhub.com", 5), ("www.pornhub.com", 5), ("ei.phncdn.com", 0), ("cv.phncdn.com", 0),
        ("www.xvideos.com", 0), ("static-ss.xvideos-cdn.com", 0), ("www.xnxx.com", 3), ("fr.xhamster.com", 5),
        ("www.tukif.com", 0), ("chaturbate.com", 0), ("nhentai.net", 0), ("www.free-porn-videos.xxx", 0)]
DATING = [("api.gotinder.com", 0), ("images-ssl.gotinder.com", 0), ("tinder.com", 0),
          ("api.badoo.com", 0), ("www.meetic.fr", 0), ("yubo.live", 0)]
CHAT = [("www.omegle.com", 0), ("ome.tv", 0)]


def entry(t, host, ip, reason=0, service=""):
    result = {}
    if reason:
        result = {"IsFiltered": True, "Reason": reason, "Rule": "||%s^" % host.split(".", 1)[-1], "FilterID": 1}
        if service:
            result["ServiceName"] = service
    return {"T": t.strftime("%Y-%m-%dT%H:%M:%S.") + "%06d000" % t.microsecond + "+02:00",
            "QH": host, "QT": "A", "QC": "IN", "CP": "", "Answer": "", "Result": result,
            "Elapsed": random.randint(100000, 9000000), "Upstream": "https://dns.quad9.net:443/dns-query", "IP": ip}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sortie", nargs="?", default="exemples/querylog.json")
    ap.add_argument("--jours", type=int, default=14)
    ap.add_argument("--graine", type=int, default=42)
    args = ap.parse_args()
    random.seed(args.graine)
    rows = []
    today = dt.date.today()
    for n in range(args.jours):
        day = today - dt.timedelta(days=args.jours - 1 - n)
        base = dt.datetime.combine(day, dt.time(0, 0), TZ)
        # trafic normal iPhone : 7h-23h30
        for _ in range(random.randint(250, 400)):
            t = base + dt.timedelta(minutes=random.randint(7 * 60, 23 * 60 + 30), seconds=random.randint(0, 59))
            rows.append(entry(t, random.choice(NORMAL), "192.168.1.42"))
        # PC : 18h-22h
        for _ in range(random.randint(80, 150)):
            t = base + dt.timedelta(minutes=random.randint(18 * 60, 22 * 60), seconds=random.randint(0, 59))
            rows.append(entry(t, random.choice(PC), "192.168.1.20"))
        # Android : 8h-21h, appli de rencontres à midi un jour sur deux
        for _ in range(random.randint(100, 180)):
            t = base + dt.timedelta(minutes=random.randint(8 * 60, 21 * 60), seconds=random.randint(0, 59))
            rows.append(entry(t, random.choice(ANDROID), "192.168.1.31"))
        if n % 2 == 0:
            t = base + dt.timedelta(hours=12, minutes=random.randint(15, 45))
            for k in range(random.randint(5, 12)):
                host, reason = random.choice(DATING[:3])
                rows.append(entry(t + dt.timedelta(seconds=20 * k), host, "192.168.1.31", reason))
        # iPhone : session sensible la nuit 4 jours sur 7, plus longue le week-end
        weekend = day.weekday() >= 5
        if random.random() < (0.85 if weekend else 0.55):
            start = base + dt.timedelta(hours=22, minutes=random.randint(10, 59))
            if weekend:
                start += dt.timedelta(hours=1)
            n_req = random.randint(15, 40) if weekend else random.randint(6, 20)
            t = start
            for _ in range(n_req):
                t += dt.timedelta(seconds=random.randint(5, 240))
                host, reason = random.choice(PORN)
                rows.append(entry(t, host, "192.168.1.42", reason))
                if random.random() < 0.3:
                    rows.append(entry(t + dt.timedelta(seconds=2), random.choice(NORMAL), "192.168.1.42"))
        # iPhone : Yubo / Omegle en fin d'après-midi le mercredi et le samedi
        if day.weekday() in (2, 5):
            t = base + dt.timedelta(hours=17, minutes=random.randint(0, 50))
            for k in range(random.randint(3, 8)):
                host, reason = random.choice(DATING[-1:] + CHAT)
                rows.append(entry(t + dt.timedelta(seconds=45 * k), host, "192.168.1.42", reason))
    rows.sort(key=lambda r: r["T"])
    with open(args.sortie, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, separators=(",", ":")) + "\n")
    print("%d requêtes écrites dans %s" % (len(rows), args.sortie))


if __name__ == "__main__":
    main()
