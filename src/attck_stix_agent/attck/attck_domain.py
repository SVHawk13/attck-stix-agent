from enum import Enum


class AttckDomain(str, Enum):
    ENTERPRISE = "enterprise"
    ICS = "ics"
    MOBILE = "mobile"

    def __str__(self):
        return self.value
