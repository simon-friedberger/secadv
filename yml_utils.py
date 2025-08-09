#!/usr/bin/env python

from __future__ import print_function

import re
import sys
import base64
import requests
import datetime
import os

try:
    from apikey import APIKEY
except:
    APIKEY = os.environ.get("BUGZILLA_API_KEY")

class Advisory:
    def __init__(self, bugJSON, advisoryText):
        self.id = bugJSON['id']
        self.product = bugJSON['product']
        self.ids = [ bugJSON['id'] ]
        self.severity = getSeverity(bugJSON)
        self.cve = bugJSON['alias'] if bugJSON['alias'] else ""
        if advisoryText is not None:
            advisory_lines = advisoryText.decode("utf-8").split("\n")
            self.title = advisory_lines[0].strip()
            if self.title == "-":
                self.title = makeTitle(bugJSON)
            self.reporter = advisory_lines[1].strip()
            self.description = "\n".join(advisory_lines[2:]).strip()
        else:
            self.title = makeTitle(bugJSON)
            self.reporter = cleanUpRealName(bugJSON)
            self.description = ""
    def pprint(self):
        print(self.id)
        print("\t", self.severity)
        print("\t", self.title)
        print("\t", self.reporter)
        print("\t", self.description)
        print("\t")
    def getCVE(self):
        if self.cve:
            return self.cve
        return f"MFSA-RESERVE-{datetime.date.today().year}-{self.id}"
    def getProduct(self):
        if self.product:
            return self.product
    def getTitle(self):
        if ":" in self.title:
            return "'" + self.title + "'"
        return self.title
    @staticmethod
    def is_reference(advisoryText):
        advisory_lines = advisoryText.decode("utf-8").split("\n")
        if "ref:" in advisory_lines[0]:
            return int(advisory_lines[0].replace("ref:", "").strip())
        return None

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def cleanUpRealName(bugJSON):
    bzName = bugJSON['creator_detail']['real_name']
    name = re.sub(r" \([^\)]+\)", "", bzName) # remove anything in parentheses
    name = re.sub(r" \[[^\]]+\]", "", name) # remove anything in brackets
    name = re.sub(" --.*", "", name) # remove anything after  --
    lookup = {
        'az': 'Ashley Zebrowski',
    }
    if name in lookup:
        name = lookup[name]
    if name != bzName:
        eprint(f"Using name '{name}' for Bug {bugJSON['id']} derived from {bzName}")
    return name

def makeTitle(bugJSON):
    return f"{getCsectype(bugJSON)} in the {getComponent(bugJSON)} component of {getProduct(bugJSON)}"

def getCsectype(bugJSON):
    causes = []
    effects = []
    for keyword in bugJSON['keywords']:
        if not keyword.startswith("csectype-"):
            continue
        match keyword:
            case "csectype-sandbox-escape":
                effects.append("sandbox escape")
            case "csectype-spoof":
                effects.append("spoofing issue")
            case "csectype-dos":
                effects.append("denial-of-service")
            case "csectype-oom":
                causes.append("out-of-memory")
            case "csectype-uninitialized":
                causes.append("uninitialized memory")
            case "csectype-wildptr":
                causes.append("invalid pointer")
            case "csectype-sop":
                effects.append("same-origin policy bypass")
            case _:
                raise Exception(f"Bug {bugJSON['id']} has unknown csectype- keyword: {keyword}")

    whatandwhy = effects + causes
    if len(whatandwhy) == 0:
        raise Exception(f"Bug {bugJSON['id']} has no csectype- keywords: {bugJSON['keywords']}")
    if len(whatandwhy) > 2:
        raise Exception(f"Bug {bugJSON['id']} has too many csectype- keywords: {bugJSON['keywords']}")

    return " due to ".join(whatandwhy)

def getComponent(bugJSON):
    bzProd = bugJSON['product']
    if bzProd in ["Core"]:
        return bzProd + " - " + bugJSON["component"]
    return bugJSON["component"]

def getProduct(bugJSON):
    bzProd = bugJSON['product']
    if bzProd in ["Firefox for Android"]:
        return "Firefox for Android"
    if bzProd in ["Focus"]:
        return "Firefox Focus for Android"
    if bzProd in ["GeckoView"]:
        return "Firefox and Firefox Focus for Android"
    if bzProd in ["Firefox", "Core", "DevTools", "WebExtensions"]:
        return "Firefox"
    raise NotImplementedError(f"Please define product string for {bugJSON['product']} for bug {bugJSON['id']}")

def getSeverity(bugJSON):
    severity = None
    for k in bugJSON['keywords']:
        if k in ["sec-critical", "sec-high", "sec-moderate", "sec-low"]:
            thisSev = k.replace("sec-", "")
            if severity is not None:
                severity = getMaxSeverity(severity, thisSev)
            else:
                severity = thisSev
    if severity is None:
        raise Exception(f"Bug {bugJSON['id']} is missing a sec keyword")
    return severity

def sortAdvisories(advisories):
    for a in advisories:
        if a.severity == "critical":
            yield a
    for a in advisories:
        if a.severity == "high":
            yield a
    for a in advisories:
        if a.severity == "moderate":
            yield a
    for a in advisories:
        if a.severity == "low":
            yield a

def bugLinkToRest(link):
    return link.replace("/buglist.cgi?", "/rest/bug?")

def doBugRequest(link, api_key):
    headers = { "X-Bugzilla-Api-Key": api_key }
    r = requests.get(bugLinkToRest(link), headers=headers)
    if r.status_code != 200:
        eprint(f"Bugzilla API returned status {r.status_code}")
    try:
        bugs = r.json()
        res = bugs['bugs']
    except Exception as e:
        eprint(f"Failed to parse Bugzilla output")
        eprint(f"JSON:")
        eprint(bugs)
        eprint(f"Exception")
        eprint(e)
        raise e
    return res

def getAdvisoryAttachment(bugid):
    link = "https://bugzilla.mozilla.org/rest/bug/" + str(bugid) + "/attachment?api_key=" + APIKEY
    r = requests.get(link)
    try:
        attachments = r.json()['bugs'][str(bugid)]
    except:
        raise Exception("Couldn't parse " + str(bugid) + "'s response for a list of attachments.  Response:\n\n" + str(r.text))
    advisory = None
    for a in attachments:
        if a['description'] == "advisory.txt" and not a['is_obsolete']:
            if advisory is not None:
                raise Exception(str(bugid) + " has two advisory.txt attachments")
            advisory = base64.b64decode(a['data'])
    return advisory

def getMaxSeverity(current, this):
    if this == "critical":
        return "critical"
    elif current in ["low", "moderate"] and this == "high":
        return "high"
    elif current in ["low"] and this == "moderate":
        return "moderate"
    return current

def sanityCheckBugs(bugs, require_cves=False):
    retvalue = True
    for b in bugs:
        bugid = b['id']
        # Check for CVE
        if require_cves and not b['alias']:
            eprint(bugid, "is missing a CVE identified. Please contact Tom Ritter (cc Dan Veditz) to have one assigned.")
            retvalue = False

        # Check for severity keywords
        try:
            getSeverity(b)
        except Exception as e:
            eprint(bugid, "seems to have some problem with the severity. If you can resolve it, please do, otherwise contact Tom Ritter (and/or Dan Veditz)")
            eprint("Exception:")
            eprint(e)
            retvalue = False

        # Check if the bug is fixed or not
        if b['status'] != "RESOLVED" and b['status'] != "VERIFIED":
            eprint(bugid, "is not marked as fixed, but is marked for this version")
            retvalue = False

    return retvalue

def pretty_text_list(words):
    if len(words) == 1:
        return words[0]
    return " and ".join([", ".join(words[:-1]), words[-1]])

