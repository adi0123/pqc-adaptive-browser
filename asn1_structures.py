from dataclasses import dataclass, field


@dataclass
class ASN1Node:

    tag: int

    length: int

    value: bytes

    children: list = field(default_factory=list)
