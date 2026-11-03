"""Read-only view of the Docker host: running images, their references, events"""

from __future__ import annotations

import docker
from docker.errors import DockerException, NotFound

from .util import hex_id


class DockerHost:
    def __init__(self, client: docker.DockerClient | None = None) -> None:
        self.client = client or docker.from_env(timeout=120)

    def running_images(self) -> dict:
        """{image_id: {"containers": set[str], "refs": set[str]}} for running containers"""

        out: dict = {}

        for c in self.client.containers.list(ignore_removed=True):
            img_id = c.attrs.get("Image")

            if not img_id:
                continue

            entry = out.setdefault(img_id, {"containers": set(), "refs": set()})

            entry["containers"].add(c.name)

            ref = (c.attrs.get("Config") or {}).get("Image")

            if ref:
                entry["refs"].add(ref)

        return out

    def candidate_refs(self, image_id: str, hints) -> list[str]:
        """References that resolve to exactly this image ID, most readable first

        A tag may have moved on to a newer image since the container started
        (pulled but not recreated), so each one is checked against the ID
        """

        try:
            img = self.client.images.get(image_id)
            tags, digests = img.tags, img.attrs.get("RepoDigests") or []
        except DockerException:
            tags, digests = [], []

        refs: list[str] = []

        for r in list(hints) + list(tags):
            if not r or r in refs or r.startswith("sha256:"):
                continue

            try:
                if self.client.images.get(r).id == image_id:
                    refs.append(r)
            except DockerException:
                pass

        refs += [d for d in digests if d not in refs]

        refs.append(hex_id(image_id))

        return refs

    def has_image(self, image_id: str) -> bool:
        try:
            self.client.images.get(image_id)

            return True
        except NotFound:
            return False

    def events(self, types: list[str], events: list[str]):
        """Yields (image_id, ref hint) for each matching event. Blocks; ends when the stream closes"""

        for ev in self.client.events(
            decode=True, filters={"type": types, "event": events}
        ):
            actor = ev.get("Actor") or {}
            ref = (actor.get("Attributes") or {}).get("image") or actor.get("ID")

            try:
                if ev.get("Type") == "container":
                    img_id = self.client.containers.get(ev["id"]).attrs["Image"]
                else:
                    img_id = self.client.images.get(ev["id"]).id
            except (NotFound, KeyError):
                continue

            yield img_id, ref
