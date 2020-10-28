#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Magnus Appelquist 2014-06-02 Initial
#

import os
import telebot
import configparser
import time
from pytimeparse.timeparse import timeparse
from tinydb import TinyDB, Query

db = TinyDB('/var/tmp/db.json')
bi = None

import requests, json, hashlib, sys


def find_new_alerts():
    new_alerts = []
    cameras = bi.cmd("camlist")
    for camera in cameras:
        if "active" not in camera:
            continue
        alerts = bi.cmd("alertlist", {"camera": camera["optionDisplay"]})
        for alert in alerts:
            Alert = Query()
            stored_alerts = db.search((Alert.date == alert["date"]) & (Alert.path == alert["path"]))

            if not stored_alerts:
                db.insert(alert)

            if int(time.time()) - alert["date"] > 3600:
                continue

            if not stored_alerts:
                new_alerts.append(alert)

    cleanup_database()
    return new_alerts


def cleanup_database():
    stored_alert = db.all()
    Alert = Query()
    for alert in stored_alert:
        if int(time.time()) - alert["date"] > 8035200:
            db.remove((Alert.date == alert["date"]) & (Alert.path == alert["path"]))


def main():
    global bi
    config_path = "/etc/bi2tg/settings.ini"
    config = configparser.ConfigParser()
    config.read(config_path)
    alerts_to_process = []
    export_request_to_alert = {}
    short_videos = {}
    short_videos_sent = {}

    bi = BlueIris(config.get("bi5", "host"), config.get("bi5", "login"), config.get("bi5", "password"), False)

    tb = telebot.TeleBot(config.get("tg", "token"), parse_mode=None)

    while 1:
        new_alerts = find_new_alerts()
        for alert in new_alerts:
            alerts_to_process.append(alert)

        # print("Alerts to process: %d" % len(alerts_to_process))

        for alert in alerts_to_process:
            current_clip = bi.cmd("clipstats", {"path": alert["path"]})
            alerts = bi.cmd("alertlist",
                            {"camera": alert["camera"], "startdate": alert["date"] - 1, "enddate": alert["date"] + 1})
            current_alert_data = {}
            for temp_alert in alerts:
                if temp_alert["date"] == alert["date"]:
                    current_alert_data = temp_alert
                    break

            if current_alert_data["offset"] > current_clip["msec"]:
                continue

            alert_duration = timeparse(current_alert_data["filesize"])

            if alert_duration > 0:
                print("Alert %s duration %d" % (current_alert_data["path"], alert_duration))
                msec = alert_duration * 1000
                alerts_to_process.remove(alert)
                export_request = bi.cmd("export",
                                        {"path": alert["path"], "profile": 1, "startms": current_alert_data["offset"],
                                         "msec": msec})
                export_request_to_alert[export_request["path"]] = alert["path"]

            else:
                if int(time.time()) - current_alert_data["date"] > 15 and (
                        "last_sent" not in alert or int(time.time()) - alert["last_sent"] > 15):
                    print(
                        "Alert %s has no duration, but 15 seconds passed sending 15 seconds now and waiting for complete clip" %
                        current_alert_data["path"])
                    if "last_sent" not in alert:
                        msec = 15000
                    else:
                        msec = (int(time.time()) - alert["last_sent"]) * 1000

                    alert["last_sent"] = int(time.time())

                    export_request = bi.cmd("export", {"path": alert["path"], "profile": 1, "startms": alert["offset"],
                                                       "msec": msec})
                    alert["offset"] += msec
                    export_request_to_alert[export_request["path"]] = alert["path"]

                    if alert["path"] not in short_videos:
                        short_videos[alert["path"]] = []

                    short_videos[alert["path"]].append(export_request["path"])

                else:
                    continue

        export_queue = bi.cmd("export")
        totalQueue = len(export_queue)
        while totalQueue > 0:
            print("Files in export queue: %s, waiting for export to finish" % totalQueue)
            for item in export_queue:
                if item["status"] == "done":

                    file_name = item["uri"]
                    tmp_file_name = "/tmp/" + file_name

                    bi.download_file("http://" + config.get("bi5", "host") + "/clips/" + file_name, tmp_file_name)
                    bi.cmd("delclip", {"path": item["path"]})

                    file_size = get_file_size_mb(tmp_file_name)
                    if file_size > 50:
                        tb.send_message(config.get("tg", "chat_id"),
                                        "file" + tmp_file_name + "is too large to send: " + str(file_size) + "Mb")
                        continue

                    video = open(tmp_file_name, 'rb')
                    print("sending %s to Telegram chat %s" % (tmp_file_name, config.get("tg", "chat_id")))
                    msg = tb.send_video(config.get("tg", "chat_id"), video, supports_streaming=1, timeout=300)

                    if item["path"] in export_request_to_alert:
                        alert_path = export_request_to_alert[item["path"]]
                        del export_request_to_alert[item["path"]]

                        if alert_path in short_videos:
                            if item["path"] in short_videos[alert_path]:
                                if alert_path not in short_videos_sent:
                                    short_videos_sent[alert_path] = []
                                short_videos_sent[alert_path].append(msg)

                            else:
                                for msg in short_videos_sent[alert_path]:
                                    tb.delete_message(msg.chat.id, msg.message_id)
                                del short_videos_sent[alert_path]

                    os.unlink(tmp_file_name)

            time.sleep(5)
            export_queue = bi.cmd("export")
            totalQueue = len(export_queue)

        time.sleep(10)


def get_file_size_mb(file_path):
    size = os.path.getsize(file_path)
    return round(size / (1024 * 1024), 3)


class BlueIris:
    session = None
    response = None
    signals = ['red', 'green', 'yellow']

    def __init__(self, host, user, password, debug=False):
        self.host = host
        self.user = user
        self.password = password
        self.debug = debug
        self.url = "http://" + host + "/json"
        r = requests.post(self.url, data=json.dumps({"cmd": "login"}))
        if r.status_code != 200:
            # print(r.status_code)
            # print(r.text)
            sys.exit(1)

        self.session = r.json()["session"]
        self.response = hashlib.md5(("%s:%s:%s" % (user, self.session, password)).encode("utf-8")).hexdigest()
        if self.debug:
            print("session: %s response: %s" % (self.session, self.response))

        r = requests.post(self.url,
                          data=json.dumps({"cmd": "login", "session": self.session, "response": self.response}))
        if r.status_code != 200 or r.json()["result"] != "success":
            print(r.status_code)
            print(r.text)
            sys.exit(1)
        self.system_name = r.json()["data"]["system name"]
        self.profiles_list = r.json()["data"]["profiles"]

        # print("Connected to '%s'" % self.system_name)

    def download_file(self, url, output):
        cookies = {"session": self.session}
        r = requests.get(url, allow_redirects=True, cookies=cookies)
        open(output, 'wb').write(r.content)

    def cmd(self, cmd, params=dict()):
        args = {"session": self.session, "cmd": cmd}
        args.update(params)

        # print(self.url)
        # print("Sending Data: ")
        # print(json.dumps(args))
        r = requests.post(self.url, data=json.dumps(args))

        if r.status_code != 200:
            print(r.status_code)
            print(r.text)
            sys.exit(1)
        else:
            pass
            # print("success: " + str(r.status_code)
            # print(r.text

        if self.debug:
            print(str(r.json()))

        try:
            return r.json()["data"]
        except:
            return r.json()

    def logout(self):
        self.cmd("logout")


if __name__ == "__main__":
    main()
