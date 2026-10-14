package Lovelace_Mb_Crc_Step_Pkg with SPARK_Mode, Pure is

   --  CRC-16/MODBUS, one step at a time [SER s.2.5.1.2, s.6.2.2].
   --  The 16-bit register is preloaded with all ones (FFFF hex). Each 8-bit byte is
   --  exclusive ORed into the register's low-order byte; then eight times the register is
   --  shifted one bit toward the LSB, zero-filling the MSB, and when the bit shifted out
   --  was 1 the register is exclusive ORed with the polynomial value A001 hex.
   --  The loop over a frame's bytes lives in the caller (the adu-framer edge); this
   --  package proves the step.

   type Crc_Register is mod 2 ** 16;
   subtype Crc_Octet is Crc_Register range 0 .. 255;

   Crc_Init : constant := 16#FFFF#;
   Crc_Poly : constant := 16#A001#;

   function Shift_Once (C : Crc_Register) return Crc_Register is
     (if C mod 2 = 1 then (C / 2) xor Crc_Poly else C / 2)
     with Post => Shift_Once'Result / 2 ** 15 = C mod 2
                  and then (if C mod 2 = 0 then Shift_Once'Result = C / 2);

   function Shift_Eight (C : Crc_Register) return Crc_Register is
     (Shift_Once (Shift_Once (Shift_Once (Shift_Once
        (Shift_Once (Shift_Once (Shift_Once (Shift_Once (C)))))))));

   function Byte_Step (Crc : Crc_Register; B : Crc_Octet) return Crc_Register is
     (Shift_Eight (Crc xor B))
     with Post => Byte_Step'Result = ((Crc / 256) xor Shift_Eight ((Crc xor B) mod 256));

   --  The CRC-16/MODBUS check value: the CRC of the nine ASCII bytes "123456789".
   function Check_Value return Crc_Register is
     (Byte_Step (Byte_Step (Byte_Step (Byte_Step (Byte_Step (Byte_Step (Byte_Step
        (Byte_Step (Byte_Step (Crc_Init, 16#31#), 16#32#), 16#33#), 16#34#), 16#35#),
        16#36#), 16#37#), 16#38#), 16#39#))
     with Post => Check_Value'Result = 16#4B37#;

   --  The worked example of [SER s.6.2.2]: the frame 02 07 gives 1241 hex.
   function Spec_Example_Value return Crc_Register is
     (Byte_Step (Byte_Step (Crc_Init, 16#02#), 16#07#))
     with Post => Spec_Example_Value'Result = 16#1241#;

end Lovelace_Mb_Crc_Step_Pkg;
