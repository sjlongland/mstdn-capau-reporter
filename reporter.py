#!/usr/bin/env python3

# CAP-AU Mastodon alerter tool
# © 2024 Stuart Longland
# SPDX-License-Identifier: MIT

import argparse
import datetime
import enum
import logging
import json
import os
import os.path
import re
import sqlite3
import tempfile

from mastodon import Mastodon
import jinja2
import lxml.etree
import requests
import staticmaps
import yaml

# Tag creation regexes
UNSAFE_TAG_CHARS_RE = re.compile(r"[^A-Za-z0-9 ]+")

# Maidenhead constants
FIELD_LNG_ANGLE = 20
FIELD_LAT_ANGLE = 10
GRID_LNG_ANGLE = 2
GRID_LAT_ANGLE = 1
CHR_A = ord("A")

# CAP-AU XML namespace
CAP_NS = {"cap": "urn:oasis:names:tc:emergency:cap:1.2"}


# CAP-AU severity levels
class SeverityLevel(enum.IntEnum):
    Unknown = 0
    Minor = 1
    Moderate = 2
    Severe = 3
    Extreme = 4


# Jinja2 template environment
jinja2_env = jinja2.Environment(autoescape=jinja2.select_autoescape())

# Clean-up regexes for QFES alerts
BR_RE = re.compile(r"<br */*>")
A_RE = re.compile(r'<a *href="([^"]+)" *>([^<>]+)</a>')

ap = argparse.ArgumentParser()
ap.add_argument(
    "--dry-run",
    help="Capture data, but don't record changes",
    action="store_const",
    default=False,
    const=True,
)
ap.add_argument("config_yml", help="Configuration File")

args = ap.parse_args()

config = yaml.safe_load(open(args.config_yml, "r").read())
MIN_SEV_LEVEL = SeverityLevel[config.get("min_severity_level", "Moderate")]
STYLES = config.get("styles", {})
ZOOM_LEVELS = config.get("zoom_levels", ["auto"])
MAP_DIMENSIONS = config.get("map_size", dict(width=800, height=500))

status_db = sqlite3.connect(config["status_db"])
mastodon = Mastodon(**config["mastodon"])
rqsession = requests.Session()

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("capau_alerter")

status_db.execute(
    """
CREATE TABLE IF NOT EXISTS sources (
    src TEXT NOT NULL,
    uri TEXT NOT NULL,
    etag TEXT NOT NULL,
    PRIMARY KEY (src) ON CONFLICT REPLACE
);
"""
)

status_db.execute(
    """
CREATE TABLE IF NOT EXISTS alerts (
    src TEXT NOT NULL,
    -- alert fields --
    msg_id TEXT NOT NULL,
    msg_status TEXT NOT NULL,
    msg_sent TEXT NOT NULL,
    msg_type TEXT NOT NULL,
    msg_scope TEXT NOT NULL,
    -- alert info fields --
    info_language TEXT NOT NULL,
    info_category TEXT NOT NULL,
    info_res_type TEXT NOT NULL,
    info_certainty TEXT NOT NULL,
    info_expires TEXT NOT NULL,
    info_sender TEXT NOT NULL,
    info_severity TEXT NOT NULL,
    info_headline TEXT NOT NULL,
    info_description TEXT NOT NULL,
    info_instruction TEXT NOT NULL,
    info_polygon TEXT,
    info_lat REAL,
    info_lng REAL,
    info_radius REAL,
    -- Mastodon fields --
    mstdn_status_id INTEGER,
    -- Column constraints --
    PRIMARY KEY (src, msg_id) ON CONFLICT REPLACE
);
"""
)


class TagRegex(object):
    def __init__(self, field, regex, tags, log):
        self._field = field
        self._tags = tags
        self._log = log
        try:
            self._regex = re.compile(regex)
        except:
            log.exception(
                "Failed to compile regex %r for field %r", regex, field
            )
            raise

    def extract(self, alert_tags):
        if self._field not in alert_tags:
            self._log.debug("%r not in %r", self._field, alert_tags)
            return

        field = alert_tags[self._field]
        match = self._regex.match(field)

        if not match:
            self._log.debug(
                "%r does not match %r in %r",
                self._field,
                self._regex,
                alert_tags,
            )
            return

        for tagconfig, matchvalue in zip(self._tags, match.groups()):
            if matchvalue is None:
                continue
            template = jinja2_env.from_string(tagconfig["template"])

            if "transform" in tagconfig:
                values = eval(
                    tagconfig["transform"], {}, dict(tag=matchvalue)
                )
                self._log.debug("Transformed %r to %r", matchvalue, values)
            else:
                values = [matchvalue]

            for matchvalue in values:
                tagvalue = template.render(tag=matchvalue)
                tag = self.mktag(tagvalue)
                self._log.debug(
                    "Extracted from %r tag %r: %r", matchvalue, tagvalue, tag
                )
                yield tag

    @staticmethod
    def mktag(s):
        s = UNSAFE_TAG_CHARS_RE.sub("", s).strip()
        return "".join((w.title() for w in s.split(" ")))


def get_gridsq(lat, lng):
    # Offset the latitude / longitude so 0, 0 corresponds to the western
    # part of Antarctica
    lng += 180
    lat += 90

    # Helper: translate a number 0-17 to a letter A-R
    letter = lambda idx: chr(CHR_A + idx)

    # Field
    fieldn_lat = int(lat / FIELD_LAT_ANGLE)
    fieldn_lng = int(lng / FIELD_LNG_ANGLE)

    # Grid square
    rem_lng = lng - (fieldn_lng * FIELD_LNG_ANGLE)
    rem_lat = lat - (fieldn_lat * FIELD_LAT_ANGLE)

    gridn_lng = int(rem_lng) / GRID_LNG_ANGLE
    gridn_lat = int(rem_lat) / GRID_LAT_ANGLE

    return "%s%s%d%d" % (
        letter(fieldn_lng),
        letter(fieldn_lat),
        gridn_lng,
        gridn_lat,
    )


def cleanup_html(text):
    # Strip carriage returns
    text = text.replace("\r", "")

    # Replace <br /> with newline
    while BR_RE.search(text):
        text = BR_RE.sub("\n", text)

    # Replace hyperlinks
    while A_RE.search(text):
        text = A_RE.sub(r"\1 ← \2", text)

    return text


def update_db(src, alert_tags, mstdn_status_id=None):
    if args.dry_run:
        log.info("Dry run mode, not updating status")
        return

    status_db.execute(
        """
INSERT INTO alerts (
    src,
    -- alert fields --
    msg_id,
    msg_status,
    msg_sent,
    msg_type,
    msg_scope,
    -- alert info fields --
    info_language,
    info_category,
    info_res_type,
    info_certainty,
    info_expires,
    info_sender,
    info_severity,
    info_headline,
    info_description,
    info_instruction,
    info_polygon,
    info_lat,
    info_lng,
    info_radius,
    mstdn_status_id
) VALUES (
    ?, -- src
    ?, -- msg_id
    ?, -- msg_status
    ?, -- msg_sent
    ?, -- msg_type
    ?, -- msg_scope
    ?, -- info_language
    ?, -- info_category
    ?, -- info_res_type
    ?, -- info_certainty
    ?, -- info_expires
    ?, -- info_sender
    ?, -- info_severity
    ?, -- info_headline
    ?, -- info_description
    ?, -- info_instruction
    ?, -- info_polygon
    ?, -- info_lat
    ?, -- info_lng
    ?, -- info_radius
    ?  -- mstdn_status_id
);""",
        (
            src,  # src
            alert_tags["identifier"],  # msg_id
            alert_tags["status"],  # msg_status
            alert_tags["sent"],  # msg_sent
            alert_tags["msgType"],  # msg_type
            alert_tags["scope"],  # msg_scope
            alert_tags["language"],  # info_language
            alert_tags["category"],  # info_category
            alert_tags["responseType"],  # info_res_type
            alert_tags["certainty"],  # info_certainty
            alert_tags["expires"],  # info_expires
            alert_tags["senderName"],  # info_sender
            alert_tags["severity"],  # info_severity
            alert_tags["headline"],  # info_headline
            alert_tags["description"],  # info_description
            alert_tags["instruction"],  # info_instruction
            # info_polygon:
            (
                json.dumps([list(c) for c in alert_tags["polygon"]])
                if "polygon" in alert_tags
                else None
            ),
            (
                alert_tags["position"][0]
                if "position" in alert_tags
                else None
            ),  # info_lat
            (
                alert_tags["position"][1]
                if "position" in alert_tags
                else None
            ),  # info_lng
            (
                alert_tags["radius"] if "radius" in alert_tags else None
            ),  # info_radius
            mstdn_status_id,
        ),
    )
    status_db.commit()


with tempfile.TemporaryDirectory() as tmpdir:
    for src, src_cfg in config["sources"].items():
        src_log = log.getChild("sources.%s" % src)

        if isinstance(src_cfg, str):
            src_cfg = dict(uri=src_cfg)

        post_template_src = src_cfg.get(
            "post_template", config.get("post_template")
        )
        assert (
            post_template_src is not None
        ), "Post template must be defined either globally or per source"
        post_template = jinja2_env.from_string(post_template_src)

        tagregexes = [
            TagRegex(**tagcfg, log=src_log.getChild("tagregex%d" % idx))
            for (idx, tagcfg) in enumerate(src_cfg.get("tagregex", []))
        ]

        # Look for the last ETag value
        src_last = None
        cur = status_db.cursor()
        cur.execute(
            "SELECT * FROM sources WHERE src=?;",
            (src,),
        )
        for row in cur:
            src_last = dict(zip((c[0] for c in cur.description), row))
            break

        if (src_last is not None) and (src_last["uri"] != src_cfg["uri"]):
            src_last = None

        if src_last is not None:
            response = rqsession.head(src_cfg["uri"])
            try:
                if src_last["etag"] == response.headers["Etag"]:
                    src_log.info("Source file has not changed")
                    continue
            except KeyError:
                pass

        src_file = os.path.join(tmpdir, "%s.xml" % src)

        response = rqsession.get(src_cfg["uri"])
        with open(src_file, "w") as f:
            f.write(response.text)

        if "ETag" in response.headers:
            if args.dry_run:
                log.info("Dry run mode, not updating status")
            else:
                status_db.execute(
                    """
                    INSERT INTO sources (src, uri, etag) VALUES (?, ?, ?);
                """,
                    (src, src_cfg["uri"], response.headers["ETag"]),
                )
                status_db.commit()
                src_log.info("Source file ETag recorded")

        alerts_xmldoc = lxml.etree.parse(src_file)
        for alert in alerts_xmldoc.iterfind(
            ".//cap:alert", namespaces=CAP_NS
        ):

            alert_tags = dict(
                [
                    (t, alert.find("./cap:%s" % t, namespaces=CAP_NS).text)
                    for t in (
                        "identifier",
                        "sent",
                        "status",
                        "msgType",
                        "scope",
                    )
                ]
            )

            alert_log = log.getChild("alert.%s" % alert_tags["identifier"])

            # Look for the alert in the database
            cur = status_db.cursor()
            cur.execute(
                "SELECT * FROM alerts WHERE src=? AND msg_id=?;",
                (src, alert_tags["identifier"]),
            )
            db_alert = None
            mstdn_status_id = None
            for row in cur:
                db_alert = dict(zip((c[0] for c in cur.description), row))
                alert_log.debug("Observed %r", db_alert)
                prev_sev_level = SeverityLevel[db_alert["info_severity"]]
                mstdn_status_id = db_alert["mstdn_status_id"]
                break

            if db_alert and (db_alert["msg_sent"] == alert_tags["sent"]):
                alert_log.info("Alert is unchanged")
                continue

            alert_info = alert.find("./cap:info", namespaces=CAP_NS)
            for t in (
                "language",
                "category",
                "responseType",
                "certainty",
                "expires",
                "senderName",
                "severity",
                "headline",
                "description",
                "instruction",
            ):
                alert_tags[t] = alert_info.find(
                    "./cap:%s" % t, namespaces=CAP_NS
                ).text

            for field in ("description", "instruction"):
                if field in alert_tags:
                    alert_tags[field] = cleanup_html(alert_tags[field])

            cur_sev_level = SeverityLevel[alert_tags["severity"]]

            mstdn_tags = []
            for tagregex in tagregexes:
                mstdn_tags.extend(tagregex.extract(alert_tags))

            alert_polygon = alert_info.find(
                "./cap:area/cap:polygon", namespaces=CAP_NS
            )
            alert_circle = alert_info.find(
                "./cap:area/cap:circle", namespaces=CAP_NS
            )
            if alert_polygon is not None:
                alert_tags["polygon"] = [
                    tuple((float(v) for v in c.split(",")))
                    for c in alert_polygon.text.split(" ")
                ]

            if alert_circle is not None:
                (circle_coord_str, radius_str) = alert_circle.text.split(" ")
                alert_tags["position"] = tuple(
                    (float(v) for v in circle_coord_str.split(","))
                )
                alert_tags["radius"] = float(radius_str)
                alert_tags["grid"] = get_gridsq(*alert_tags["position"])

            alert_log.debug("Extracted alert: %r", alert_tags)
            timestamp = datetime.datetime.fromisoformat(alert_tags["sent"])

            # Do we need to do anything with this alert?
            if (cur_sev_level < MIN_SEV_LEVEL) and (
                (db_alert is None) or (prev_sev_level < MIN_SEV_LEVEL)
            ):
                alert_log.info(
                    "Ignoring alert of severity %r", alert_tags["severity"]
                )
                update_db(src, alert_tags, mstdn_status_id)
                continue

            files = []
            for zoomlevel in ZOOM_LEVELS:
                if args.dry_run:
                    alert_log.info(
                        "Skipping image at zoom level %s due to dry-run mode",
                        zoomlevel,
                    )
                    continue

                context = staticmaps.Context()
                context.set_tile_provider(staticmaps.tile_provider_OSM)

                # Style information
                style = STYLES.get("_DEFAULT_", {})
                for field, styleinfo in STYLES.items():
                    if field == "_DEFAULT_":
                        continue

                    try:
                        value = alert_tags[field]
                    except KeyError:
                        continue

                    try:
                        valuestyle = styleinfo[value]
                    except KeyError:
                        pass

                    style.update(valuestyle)

                if "polygon" in alert_tags:
                    context.add_object(
                        staticmaps.Area(
                            [
                                staticmaps.create_latlng(lat, lng)
                                for lat, lng in alert_tags["polygon"]
                            ],
                            fill_color=(
                                staticmaps.parse_color(style["fill_color"])
                                if "fill_color" in style
                                else None
                            ),
                            width=style.get("width"),
                            color=(
                                staticmaps.parse_color(style["color"])
                                if "color" in style
                                else None
                            ),
                        )
                    )
                elif ("position" in alert_tags) and ("radius" in alert_tags):
                    context.add_object(
                        staticmaps.Circle(
                            center=staticmaps.create_latlng(
                                *alert_tags["position"]
                            ),
                            radius_km=alert_tags["radius"],
                            fill_color=(
                                staticmaps.parse_color(style["fill_color"])
                                if "fill_color" in style
                                else None
                            ),
                            width=style.get("width"),
                            color=(
                                staticmaps.parse_color(style["color"])
                                if "color" in style
                                else None
                            ),
                        )
                    )
                else:
                    continue

                if zoomlevel != "auto":
                    context.set_zoom(zoomlevel)

                # render anti-aliased png (this only works if pycairo is installed)
                image = context.render_cairo(
                    MAP_DIMENSIONS["width"], MAP_DIMENSIONS["height"]
                )
                imagefile = os.path.join(
                    tmpdir,
                    "%s-%s-%s.png"
                    % (
                        alert_tags["identifier"],
                        zoomlevel,
                        timestamp.strftime("%Y%m%d-%H%M"),
                    ),
                )
                image.write_to_png(imagefile)
                files.append(imagefile)

            alert_log.info("Generated %d images", len(files))

            post_text = post_template.render(**alert_tags).rstrip()

            for tag in mstdn_tags:
                post_text += " #%s" % tag

            if args.dry_run:
                alert_log.info("Would post:\n%s", post_text)
                continue

            media_ids = [
                mastodon.media_post(media_file=file, mime_type="image/png")
                for file in files
            ]

            if mstdn_status_id is None:
                post = mastodon.status_post(
                    status=post_text,
                    media_ids=media_ids,
                )
                mstdn_status_id = post["id"]
            else:
                mastodon.status_update(
                    id=mstdn_status_id,
                    status=post_text,
                    media_ids=media_ids,
                )

            update_db(src, alert_tags, mstdn_status_id)
