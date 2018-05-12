--
-- Launch Wireshark as `wireshark -X lua_script:/home/hamster/Documents/joylink2.lua capture.pcap` to load this dissector
--
-- Fields available as joylink2.*
--

MAGIC_ENUM = {[0x123455bb] = "LAN Access", [0x123455cc] = "Cloud Access"}
ENCRYPTION_ENUM = {[0] = "Plain Text", [1] = "Static AES", [2] = "ECDH", [3] = "Dynamic AES"}
TYPE_ENUM = {[1] = "Device Discovery", [2] = "Device Authorization", [3] = "Data Transfer (JSON)",
            [4] = "Data Transfer (Script)", [7] = "OTA Upgrade", [8] = "OTA Upgrade Status Report",
            [9] = "Cloud Device Authentication", [10] = "Heartbeat", [11] = "Cloud Command",
            [12] = "Data Upload", [13] = "Scheduled Task", [14] = "Result Upload",
            [102] = "Sub-device Authorization", [103] = "LAN Sub-device Data Transfer (JSON)",
            [104] = "LAN Sub-device Data Transfer (Script)", [105] = "Sub-device Addition",
            [110] = "Sub-device Heartbeat", [111] = "Sub-device Cloud Command",
            [112] = "Sub-device Data Upload", [113] = "Sub-device Unbinding",
            [200] = "Live Stream Request", [201] = "Live Stream Response"}

joylink2_proto = Proto("joylink2","JoyLink 2.0 Protocol")

magic_F = ProtoField.uint32("joylink2.magic","Magic", base.HEX, MAGIC_ENUM)
optlen_F = ProtoField.uint16("joylink2.optlen","Option Length", base.HEX_DEC)
payloadlen_F = ProtoField.uint16("joylink2.payloadlen","Payload Length", base.HEX_DEC)
version_F = ProtoField.uint8("joylink2.version","Version", base.DEC)
type_F = ProtoField.uint8("joylink2.type","Type", base.DEC, TYPE_ENUM)
total_F = ProtoField.uint8("joylink2.total","Total of Fragments", base.DEC)
index_F = ProtoField.uint8("joylink2.index","Fragment Index")
enctype_F = ProtoField.uint8("joylink2.enctype","Encryption Type", base.DEC, ENCRYPTION_ENUM)
reserved_F = ProtoField.uint8("joylink2.reserved","Reserved")
crc_F = ProtoField.uint16("joylink2.crc","CRC (Not Checked)", base.HEX)
opt_F = ProtoField.bytes("joylink2.option", "Option")
payload_F = ProtoField.bytes("joylink2.payload", "Payload")
payload_str_F = ProtoField.string("joylink2.payload_string", "Payload (String)")

joylink2_proto.fields = {magic_F, optlen_F, payloadlen_F, version_F, type_F, total_F,
                        index_F, enctype_F, reserved_F, crc_F, opt_F, payload_F, payload_str_F}

function joylink2_proto.dissector(buf,pinfo,tree)
    -- common header is 16 bytes long
    if buf:len() < 16 then
        return false
    end

    local magic = buf(0, 4):le_uint()

    if magic ~= 0x123455bb and magic ~= 0x123455cc then
        return false
    end

    local t = tree:add(joylink2_proto, buf())

    -- common header
    t:add_le(magic_F, buf(0 ,4))
    t:add_le(optlen_F, buf(4, 2))
    t:add_le(payloadlen_F, buf(6, 2))
    t:add_le(version_F, buf(8, 1))
    t:add_le(type_F, buf(9, 1))
    t:add_le(total_F, buf(10, 1))
    t:add_le(index_F, buf(11, 1))
    t:add_le(enctype_F, buf(12, 1))
    t:add_le(reserved_F, buf(13, 1))
    t:add_le(crc_F, buf(14, 2))

    local optlen = buf(4, 2):le_uint()
    local payloadlen = buf(6, 2):le_uint()

    if optlen > 0 then
        if buf:len() - 16 >= optlen then
            t:add(opt_F, buf(16, optlen))
        else
            t:add(opt_F, buf(16), "<TRUNCATED>")
        end
    end

    local encryption = buf(12, 1):le_uint()
    local payload_field
    if encryption == 0 then
        payload_field = payload_str_F
    else
        payload_field = payload_F
    end

    if payloadlen > 0 then
        if buf:len() - 16 - optlen >= payloadlen then
            t:add(payload_field, buf(16 + optlen, payloadlen))
        else
            t:add(payload_field, buf(16 + optlen), "<TRUNCATED>")
        end
    end

    return true
end

-- QUIC will take precedence if we are heuristic
--joylink2_proto:register_heuristic("udp", joylink2_proto.dissector)

DissectorTable.get('udp.port'):add(80, joylink2_proto)
DissectorTable.get('udp.port'):add(4320, joylink2_proto)