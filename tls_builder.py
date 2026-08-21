class TLSBuilder:

    #
    # Fake Hybrid PQC Group ID
    # (Later we will replace this with the official one)
    #
    HYBRID_GROUP = 0x6399

    def __init__(self):
        pass

    #
    # Main function
    #
    def build_client_hello(self,packet, client_hello):

        groups_info = self.locate_supported_groups(
            packet
        )

        if groups_info is None:

            print(
                "Supported Groups extension not found."
            )

            return client_hello

        supported_groups = self.read_supported_groups(
            packet,
            groups_info
        )

        print("Groups:")

        for group in supported_groups:

            print(f"0x{group:04X}")

        print()

        print("========== BUILDER ==========")

        print(
            f"Supported Groups Offset : "
            f"{groups_info['offset']}"
        )

        print(
            f"Extension Length        : "
            f"{groups_info['extension_length']}"
        )

        print(
            f"Group List Length       : "
            f"{groups_info['group_list_length']}"
        )

        print("=============================")

        print()

        #
        # For now we simply rebuild the packet.
        # In the next step we will insert the PQC group.
        #
        return self.rebuild_client_hello(
            packet,
            client_hello
        )

    #
    # Locate Supported Groups Extension
    #
    def locate_supported_groups(self, packet):

        extension = b"\x00\x0A"

        index = packet.find(extension)

        if index == -1:
            return None

        extension_length = int.from_bytes(
            packet[index + 2:index + 4],
            "big"
        )

        group_list_length = int.from_bytes(
            packet[index + 4:index + 6],
            "big"
        )

        return {
            "offset": index,
            "extension_length": extension_length,
            "group_list_length": group_list_length
        }

    #
    # Read every supported group
    #
    def read_supported_groups(
        self,
        packet,
        info
    ):

        start = info["offset"] + 6

        end = start + info["group_list_length"]

        groups = []

        for i in range(start, end, 2):

            group = int.from_bytes(
                packet[i:i+2],
                "big"
            )

            groups.append(group)

        return groups

    #
    # Packet rebuilding placeholder
    #
    def rebuild_client_hello(self,packet, client_hello):

        packet = bytearray(packet)

        info = self.locate_supported_groups(packet)

        if info is None:

            return client_hello

        #
        # Offsets
        #

        extensions_length_offset = client_hello[
            "extensions_length_offset"
        ]

        group_length_offset = info["offset"] + 4

        first_group = info["offset"] + 6

        #
        # Insert after X25519
        #

        insert_position = first_group + 2

        packet[
            insert_position:insert_position
        ] = b"\x63\x99"
        
        extensions_length = client_hello[
            "extensions_length"
        ] + 2

        packet[
            client_hello["extensions_length_offset"]:
            client_hello["extensions_length_offset"] + 2
        ] = extensions_length.to_bytes(
            2,
            "big"
        )
        #
        # Update lengths
        #

        extension_length = info["extension_length"] + 2

        group_length = info["group_list_length"] + 2
        extension_length_offset = info["offset"] + 2
        packet[
            extensions_length_offset:
            extensions_length_offset + 2
        ] = extensions_length.to_bytes(
            2,
            "big"
        )

        packet[
            group_length_offset:
            group_length_offset + 2
        ] = group_length.to_bytes(
            2,
            "big"
        )

        #
        # ClientHello handshake length
        #

        handshake_length = (
            (packet[6] << 16)
            |
            (packet[7] << 8)
            |
            packet[8]
        )

        handshake_length += 2

        packet[6] = (handshake_length >> 16) & 0xff
        packet[7] = (handshake_length >> 8) & 0xff
        packet[8] = handshake_length & 0xff

        #
        # TLS Record Length
        #

        record_length = int.from_bytes(
            packet[3:5],
            "big"
        )

        record_length += 2

        packet[3:5] = record_length.to_bytes(
            2,
            "big"
        )

        print()

        print("Hybrid group inserted (0x6399)")

        return bytes(packet)

    #
    # Insert a new supported group
    #
    def insert_supported_group(
        self,
        packet,
        group_id
    ):

        packet = bytearray(packet)

        info = self.locate_supported_groups(
            packet
        )

        if info is None:
            return bytes(packet)

        #
        # Where the list begins
        #
        start = info["offset"] + 6

        #
        # Insert after first group (X25519)
        #
        insert_pos = start + 2

        packet[
            insert_pos:insert_pos
        ] = group_id.to_bytes(
            2,
            "big"
        )

        #
        # Update Supported Group List Length
        #
        new_group_length = (
            info["group_list_length"] + 2
        )

        packet[
            info["offset"] + 4:
            info["offset"] + 6
        ] = new_group_length.to_bytes(
            2,
            "big"
        )

        #
        # Update Extension Length
        #
        new_extension_length = (
            info["extension_length"] + 2
        )

        packet[
            info["offset"] + 2:
            info["offset"] + 4
        ] = new_extension_length.to_bytes(
            2,
            "big"
        )

        print()

        print("========== BUILDER ==========")

        print(
            f"Inserted Group : "
            f"0x{group_id:04X}"
        )

        print(
            f"New Extension Length : "
            f"{new_extension_length}"
        )

        print(
            f"New Group Length : "
            f"{new_group_length}"
        )

        print("=============================")

        print()

        return bytes(packet)
