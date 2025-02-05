from crc import Calculator, Crc32
import os

chunk_types = ["IHDR", "PLTE", "IDAT", "IEND"]

colour_types = {
    0: "Grayscale : each pixels has value from 0 to 255",
    2: "RGB : 3 bytes per pixel",
    3: "PLTE : 1 byte per pixels",
    4: "Grayscale with alpha : 2 bytes per pixels",
    6: "RGBA : 4 bytes per pixels",
}
compressions_types = {0: "Deflate compression"}
filter_types = {0: "Adaptive "}
interlace_types = {0: " No interlace", 1: "Adam7 interlace"}


def crc32_iso_hdlc(data):

    # Tạo đối tượng Calculator với cấu hình CRC-32/ISO-HDLC
    calculator = Calculator(Crc32.CRC32)
    # Tính toán CRC
    crc_value = calculator.checksum(data)
    return hex(crc_value)


class Chunk:
    def __init__(self):
        self.data_length = b"\x00"
        self.chunk_type = b"\x00"
        self.chunk_data = b"\x00"
        self.CRC = b"\x00"

    def read_DataLength(self, f):
        # 4 bytes
        self.data_length = f.read(4)

    def read_ChunkType(self, f):
        # 4 bytes
        self.chunk_type = f.read(4)

    def get_HashCRF(self):
        return self.chunk_type + self.chunk_data

    def read_ChunkData(self, f):
        # undefined bytes
        data_length = self.get_DataLength()
        self.chunk_data = f.read(data_length)
        if self.get_ChunkType() == "IHDR":
            # 4bytes width
            width = self.chunk_data[:4]
            # 4bytes height
            height = self.chunk_data[4:8]
            # 1bytes bit_depth
            bit_depth = self.chunk_data[8:9]
            # 1 bytes colour_type
            colour_type = self.chunk_data[9:10]
            # 1 bytes compression method
            compress_method = self.chunk_data[10:11]
            # 1 bytes filter method
            filter_method = self.chunk_data[11:12]
            # 1 bytes interlace method
            interlace_method = self.chunk_data[12:13]
            print(
                f"Width : {int(width.hex(), 16)} px",
                f"Height : {int(height.hex(), 16)} px",
                f"Bit depth : {int(bit_depth.hex(), 16)} bits per channel",
                f"Colour Type : {int(colour_type.hex(),16)};{colour_types[int(colour_type.hex(),16)]}",
                f"Compression Method : {int(compress_method.hex(),16)} {compressions_types[int(compress_method.hex(),16)]}",
                f"Filter Method : {int(filter_method.hex(),16)} {filter_types[int(filter_method.hex(),16)]}",
                f"Interlace Method : {int(interlace_method.hex(),16)} {interlace_types[int(interlace_method.hex(),16)]}",
                sep="\n",
            )

    def read_CRC(self, f):
        # 4 bytes
        self.CRC = f.read(4)

    def get_DataLength(self):
        return int(self.data_length.hex(), 16)

    def get_ChunkType(self):
        return str(bytes.fromhex(self.chunk_type.hex()).decode("utf-8"))

    def get_ChunkData(self):
        return str(self.chunk_data.hex())

    def getCRC(self):
        return str(self.CRC.hex())


def readFilePNG(filePath):
    pngSignature = bytes.fromhex("89 50 4E 47 0D 0A 1A 0A")
    chunks = []
    with open(filePath, "rb") as f:
        # read 8 bytes
        signature = f.read(8)
        if signature != pngSignature:
            print("Not valid format png")
        index = 1
        while True:
            c1 = Chunk()
            c1.read_DataLength(f)
            c1.read_ChunkType(f)
            c1.read_ChunkData(f)
            c1.read_CRC(f)
            print(f"\t\tData Chunk {index}")
            print(f"Data Length : {c1.get_DataLength()} bytes")
            print(f"Chunk Type : {c1.get_ChunkType()}")
            print(f"Chunk Data : {c1.get_ChunkData()}")
            print(f"CRC : {c1.getCRC()}")
            print(f"HASH CRC : {crc32_iso_hdlc(c1.get_HashCRF())}")
            chunks.append(c1)
            index += 1
            if c1.get_ChunkType() == "IEND":
                break


class Packet:
    def __init__(self):
        self.header = b"\x00"
        self.payload = b"\x00"

    def read_Header(self, f):
        self.header = f.read(4)

    def read_Payload(self, f):
        self.payload = f.read(184)

    def get_Header(self):
        hex_string = str(self.payload.hex())
        header_bin = bin(int(hex_string, 16))[2:]
        sync_byte = header_bin[:8]
        TEI = header_bin[8:9]
        PUSI = header_bin[9:10]
        transport_Priority = header_bin[10:11]
        PID = header_bin[11:24]
        TSC = header_bin[24:26]
        adapt_field = header_bin[26:28]
        counter = header_bin[28:32]
        print(
            f"Sync byte : {sync_byte}",
            f"Transport Error Indicator : {TEI}",
            f"Payload Unit Start Indicator : {PUSI}",
            f"Transport Priority : {transport_Priority}",
            f"PID : {PID}",
            f"Transport Scrambling Control : {TSC}",
            f"Adaptation field control : {adapt_field}",
            f"Continuty counter : {counter}",
            sep="\n",
        )

    def get_Payload(self):
        return str(self.payload.hex())


def readFileTS(filePath):
    SIZEPACKET = 188
    packets = []
    file_size = int(os.stat(filePath).st_size / SIZEPACKET)
    print(f"TOTAL PACKAGES : {file_size}")
    with open(filePath, "rb") as f:
        index = 1
        while True:
            pk = Packet()
            pk.read_Header(f)
            pk.read_Payload(f)
            packets.append(pk)
            print(f"\t\tPackage {index}")
            pk.get_Header()
            print(f"Payload : {pk.get_Payload()}")
            if index == file_size:
                break
            index += 1


# readFilePNG("assets\demo.png")
readFileTS("assets\segment_0.ts")
