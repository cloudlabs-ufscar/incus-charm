# Copyright 2021 Ubuntu
# See LICENSE file for licensing details.

"""Library for the tls-certificates relation."""

import json
import logging
import socket
from dataclasses import asdict, dataclass
from typing import List, Optional, Set

from ops import RelationChangedEvent, RelationCreatedEvent, StoredState
from ops.charm import CharmBase, CharmEvents
from ops.framework import EventBase, EventSource, Object

# The unique Charmhub library identifier, never change it
LIBID = "f3d29a1b5c8e47b9ae1f3d44b6875e1a"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

PYDEPS = ["ops>=2.0.0", "pydantic>=1.10,<2"]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Certificate:
    """A PEM encoded X509 certificate and its components."""

    cert: str
    key: str
    ca: str

    def dump(self) -> dict:
        """Dumps the certificate into a serializable dictionary."""
        return asdict(self)

    @classmethod
    def load(cls, data: Optional[dict]) -> Optional["Certificate"]:
        """Loads the certificate from a serializable dictionary."""
        if data is None:
            return None
        return cls(**data)


class CertificateChangedEvent(EventBase):
    """Charm event triggered when a certificate is changed."""

    def __init__(self, handle, certificate: Certificate):
        super().__init__(handle)
        self.certificate = certificate

    def snapshot(self) -> dict:
        """Encode the event into a snapshot."""
        return {"certificate": asdict(self.certificate)}

    def restore(self, snapshot: dict):
        """Restore the event from a snapshot."""
        self.certificate = Certificate(**snapshot["certificate"])


class CertificatesRequiresCharmEvents(CharmEvents):
    """List of events that the TLS Certificates requirer charm can leverage."""

    certificate_changed = EventSource(CertificateChangedEvent)


class TLSCertificatesRequires(Object):
    """The requires side of the tls-certificates interface v0."""

    on = CertificatesRequiresCharmEvents()
    _stored = StoredState()

    def __init__(
        self,
        charm: CharmBase,
        common_name: str = socket.getfqdn(),
        sans: List[str] = [],
        relation_name: str = "certificates",
    ):
        super().__init__(charm, relation_name)
        self.charm = charm
        self.sans = list(set(sans))
        self.sans.sort()
        self.common_name = common_name
        self.relation_name = relation_name

        self.framework.observe(charm.on[relation_name].relation_created, self._on_relation_created)
        self.framework.observe(charm.on[relation_name].relation_changed, self._on_relation_changed)

        self._stored.set_default(certificate=None)

    @property
    def certificate(self) -> Optional[Certificate]:
        """The certificate issued for the current unit."""
        return self._get_certificate_from_relation_data()

    def _on_relation_created(self, event: RelationCreatedEvent):
        """Handle relation created event on the certificates relation.

        Writes the certificate request data to the relation.
        """
        event.relation.data[self.charm.unit]["unit_name"] = self._unit_name
        event.relation.data[self.charm.unit]["certificate_name"] = self.charm.app.name
        event.relation.data[self.charm.unit]["common_name"] = self.common_name
        if self.sans:
            event.relation.data[self.charm.unit]["sans"] = json.dumps(self.sans)
        logger.debug(
            "Wrote cert request to the relation data. relation_name=%s common_name=%s sans=%s",
            self.relation_name,
            self.common_name,
            self.sans,
        )

    def _on_relation_changed(self, event: RelationChangedEvent) -> None:
        """Handler triggerred on relation changed events."""
        logger.debug("Handling certificate relation changed. data=%s", event.relation.data)
        certificate = self._get_certificate_from_relation_data()
        if not certificate:
            logger.debug(
                "Certificate not found in the relation data. relation_data=%s", event.relation.data
            )
            return

        if certificate == Certificate.load(self._stored.certificate):
            logger.debug(
                "Certificate found in the relation data was already seen. Will not emit event. certificate=%s",
                certificate,
            )
            return

        self._stored.certificate = certificate.dump()
        self.on.certificate_changed.emit(certificate=certificate)

    def _get_certificate_from_relation_data(self) -> Optional[Certificate]:
        """Retrieve the certificate for the current unit from the relation data."""
        relation = self.model.get_relation(relation_name=self.relation_name)
        if relation is None:
            logger.debug("No relation found in model. relation_name=%s", self.relation_name)
            return None
        # NOTE: when dealing with multiple vault units we need to ensure that
        # the certificate data is consistent between all units.
        certificates: Set[Certificate] = set()
        unit_name = self._unit_name
        for unit in relation.units:
            unit_data = relation.data[unit]
            ca = unit_data.get("ca")
            cert = unit_data.get(f"{unit_name}.server.cert")
            key = unit_data.get(f"{unit_name}.server.key")
            if not (ca and cert and key):
                logger.debug("Relation data incomplete. unit_data=%s", unit_data)
                return None

            certificate = Certificate(cert=cert, key=key, ca=ca)
            certificates.add(certificate)

        if len(certificates) == 0:
            logger.debug("No certificates found in the relation. certificates=%s", certificates)
            return None

        if len(certificates) > 1:
            logger.debug(
                "Multiple certificates found in the relation. Assuming the relation is inconsistent. certificates=%s",
                certificates,
            )
            return None

        return certificates.pop()

    @property
    def _unit_name(self):
        """The unit name that identifies the unit on the relation data."""
        return self.charm.unit.name.replace("/", "_")
