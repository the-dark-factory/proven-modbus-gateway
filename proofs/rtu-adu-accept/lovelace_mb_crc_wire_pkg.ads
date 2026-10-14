package Lovelace_Mb_Crc_Wire_Pkg with SPARK_Mode, Pure is

   --  The CRC on the wire [SER s.2.5.1.2, s.6.2.2 "Placing the CRC into the Message"]:
   --  the low-order byte is appended first, then the high-order byte, which is the last
   --  byte of the frame. Example: CRC 1241 hex is sent as 41 then 12.
   --  The receiver recomputes the CRC and compares it with the two bytes received.

   subtype Crc_Number is Natural range 0 .. 65_535;
   subtype Wire_Byte is Natural range 0 .. 255;

   function Low_Byte (C : Crc_Number) return Wire_Byte is
     (C mod 256);

   function High_Byte (C : Crc_Number) return Wire_Byte is
     (C / 256);

   function Wire_Value (Lo, Hi : Wire_Byte) return Crc_Number is
     (Hi * 256 + Lo)
     with Post => Low_Byte (Wire_Value'Result) = Lo
                  and then High_Byte (Wire_Value'Result) = Hi;

   function Crc_Matches (Computed : Crc_Number; Lo, Hi : Wire_Byte) return Boolean is
     (Low_Byte (Computed) = Lo and then High_Byte (Computed) = Hi)
     with Post => Crc_Matches'Result = (Computed = Wire_Value (Lo, Hi));

   function Split_Rejoins (C : Crc_Number) return Boolean is
     (Wire_Value (Low_Byte (C), High_Byte (C)) = C)
     with Post => Split_Rejoins'Result;

   --  A CRC sent high byte first: it matches only when its two bytes are equal.
   function Swapped_Matches (C : Crc_Number) return Boolean is
     (Crc_Matches (C, High_Byte (C), Low_Byte (C)))
     with Post => Swapped_Matches'Result = (Low_Byte (C) = High_Byte (C));

   --  The example of [SER s.6.2.2]: 1241 hex is sent 41, 12.
   function Spec_Example_Matches return Boolean is
     (Crc_Matches (16#1241#, 16#41#, 16#12#))
     with Post => Spec_Example_Matches'Result;

end Lovelace_Mb_Crc_Wire_Pkg;
