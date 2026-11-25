"""Prune old image tags on Docker Hub.

Keeps `latest`, the newest KEEP_RELEASES release tags (vX.Y.Z) and the
vX.Y tags of those releases. Everything else (older releases, legacy
tags without "v", branch tags like `main`) is deleted.

Env: DOCKERHUB_USERNAME, DOCKERHUB_TOKEN (PAT with Read/Write/Delete),
     IMAGE (namespace/repo), KEEP_RELEASES (default 2), DRY_RUN (true/false).
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

HUB = "https://hub.docker.com/v2"
RELEASE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def call(method, url, token=None, body=None):
    req = urllib.request.Request(url, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data, timeout=30) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as err:
        return err.code, {"error": err.read().decode(errors="replace")[:300]}


def login(user, secret):
    status, data = call("POST", f"{HUB}/auth/token", body={"identifier": user, "secret": secret})
    if status == 200 and data.get("access_token"):
        return data["access_token"]
    status, data = call("POST", f"{HUB}/users/login", body={"username": user, "password": secret})
    if status == 200 and data.get("token"):
        return data["token"]
    sys.exit(f"Docker Hub login failed (HTTP {status}): {data}")


def list_tags(image, token):
    tags, url = [], f"{HUB}/repositories/{image}/tags?page_size=100"
    while url:
        status, data = call("GET", url, token)
        if status != 200:
            sys.exit(f"cannot list tags (HTTP {status}): {data}")
        tags += [t["name"] for t in data.get("results", [])]
        url = data.get("next")
    return tags


def main():
    image = os.environ["IMAGE"]
    keep_n = int(os.environ.get("KEEP_RELEASES", "2"))
    dry = os.environ.get("DRY_RUN", "false").lower() == "true"
    token = login(os.environ["DOCKERHUB_USERNAME"], os.environ["DOCKERHUB_TOKEN"])

    tags = list_tags(image, token)
    releases = sorted(
        (t for t in tags if RELEASE.match(t)),
        key=lambda t: tuple(int(x) for x in RELEASE.match(t).groups()),
        reverse=True,
    )
    keep = {"latest", *releases[:keep_n]}
    keep |= {"v{}.{}".format(*RELEASE.match(t).groups()[:2]) for t in releases[:keep_n]}
    delete = sorted(t for t in tags if t not in keep)

    print(f"{image}: {len(tags)} tags")
    print("keep:  ", " ".join(sorted(t for t in tags if t in keep)))
    print("delete:", " ".join(delete) or "-")
    if not releases:
        sys.exit("no vX.Y.Z release tags found - refusing to delete anything")
    if dry:
        print("DRY_RUN - nothing deleted")
        return
    failed = []
    for tag in delete:
        status, data = call("DELETE", f"{HUB}/repositories/{image}/tags/{tag}/", token)
        if status in (200, 202, 204):
            print(f"deleted {tag}")
        else:
            print(f"FAILED {tag}: HTTP {status} {data}")
            failed.append(tag)
    if failed:
        sys.exit(f"{len(failed)} tag(s) not deleted - does DOCKERHUB_TOKEN have Delete permission?")


if __name__ == "__main__":
    main()
