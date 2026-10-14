package Lovelace_Mb_Fc_Catalog_Pkg with SPARK_Mode, Pure is

   --  The public function codes the gateway parses [APP s.5.1], and every other byte.
   --  In scope: 01 Read Coils, 02 Read Discrete Inputs, 03 Read Holding Registers,
   --  04 Read Input Registers, 05 Write Single Coil, 06 Write Single Register,
   --  15 Write Multiple Coils, 16 Write Multiple Registers, 22 Mask Write Register,
   --  23 Read/Write Multiple Registers, 43 Encapsulated Interface Transport (MEI 14 only).
   --  Out of scope (R-MB-10): serial-only 07, 08, 11, 12, 17; 20, 21, 24; every other byte.
   --  [APP s.4.1]: function code 0 is not valid; 128 .. 255 are reserved for exception
   --  responses. All of these are Unsupported_Fc, answered with exception 01.

   subtype Octet is Natural range 0 .. 255;

   type Function_Kind is
     (Read_Coils_Fc,
      Read_Discrete_Fc,
      Read_Holding_Fc,
      Read_Input_Fc,
      Write_Coil_Fc,
      Write_Register_Fc,
      Write_Coils_Fc,
      Write_Registers_Fc,
      Mask_Write_Fc,
      Read_Write_Fc,
      Encapsulated_Fc,
      Unsupported_Fc);

   subtype Public_Kind is Function_Kind range Read_Coils_Fc .. Encapsulated_Fc;
   subtype Read_Bits_Kind is Function_Kind range Read_Coils_Fc .. Read_Discrete_Fc;
   subtype Read_Words_Kind is Function_Kind range Read_Holding_Fc .. Read_Input_Fc;
   subtype Single_Write_Kind is Function_Kind range Write_Coil_Fc .. Write_Register_Fc;

   function Code_Of (K : Public_Kind) return Octet is
     (case K is
         when Read_Coils_Fc => 1,
         when Read_Discrete_Fc => 2,
         when Read_Holding_Fc => 3,
         when Read_Input_Fc => 4,
         when Write_Coil_Fc => 5,
         when Write_Register_Fc => 6,
         when Write_Coils_Fc => 15,
         when Write_Registers_Fc => 16,
         when Mask_Write_Fc => 22,
         when Read_Write_Fc => 23,
         when Encapsulated_Fc => 43)
     with Post => Code_Of'Result >= 1 and then Code_Of'Result < 16#80#;

   function Function_Kind_Of (B : Octet) return Function_Kind is
     (case B is
         when 1 => Read_Coils_Fc,
         when 2 => Read_Discrete_Fc,
         when 3 => Read_Holding_Fc,
         when 4 => Read_Input_Fc,
         when 5 => Write_Coil_Fc,
         when 6 => Write_Register_Fc,
         when 15 => Write_Coils_Fc,
         when 16 => Write_Registers_Fc,
         when 22 => Mask_Write_Fc,
         when 23 => Read_Write_Fc,
         when 43 => Encapsulated_Fc,
         when others => Unsupported_Fc)
     with Post => (if B = 1 or else B = 2 or else B = 3 or else B = 4 or else B = 5
                      or else B = 6 or else B = 15 or else B = 16 or else B = 22
                      or else B = 23 or else B = 43
                   then Function_Kind_Of'Result /= Unsupported_Fc
                        and then Code_Of (Function_Kind_Of'Result) = B
                   else Function_Kind_Of'Result = Unsupported_Fc);

   function Codes_Round_Trip return Boolean is
     (for all K in Public_Kind => Function_Kind_Of (Code_Of (K)) = K)
     with Post => Codes_Round_Trip'Result;

   function Is_Write_Kind (K : Function_Kind) return Boolean is
     (K = Write_Coil_Fc or else K = Write_Register_Fc or else K = Write_Coils_Fc
      or else K = Write_Registers_Fc or else K = Mask_Write_Fc or else K = Read_Write_Fc)
     with Post => Is_Write_Kind'Result
                    = (K /= Unsupported_Fc
                       and then (Code_Of (K) = 5 or else Code_Of (K) = 6 or else Code_Of (K) = 15
                                 or else Code_Of (K) = 16 or else Code_Of (K) = 22
                                 or else Code_Of (K) = 23));

   function Is_Exception_Byte (B : Octet) return Boolean is
     (B >= 16#80#)
     with Post => (if Is_Exception_Byte'Result then Function_Kind_Of (B) = Unsupported_Fc);

end Lovelace_Mb_Fc_Catalog_Pkg;
