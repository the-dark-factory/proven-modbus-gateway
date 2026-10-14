with Lovelace_Mb_Frame_Refusal_Pkg;
with Lovelace_Mb_Crc_Wire_Pkg;

package Lovelace_Mb_Rtu_Accept_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Frame_Refusal_Pkg.Frame_Verdict;

   --  The RTU ADU verdict [SER s.2.2, s.2.5.1, s.2.5.1.1, s.2.5.1.2].
   --  A frame of N bytes: byte 1 the address, bytes 2 .. N-2 the PDU, bytes N-1, N the CRC
   --  (low byte first). Computed is the CRC of bytes 1 .. N-2, swept by the caller.
   --  N is 4 .. 256: address, function code and CRC at least; 256 at most [SER s.2.5.1].
   --  Addresses [SER s.2.2]: 0 broadcast, 1 .. 247 individual, 248 .. 255 reserved.
   --  The CRC is checked before the address is analysed [SER s.2.5.1.1, figure 14 notes].
   --  Every refusal is silent (Lovelace_Mb_Frame_Refusal_Pkg.Frame_Answer, R-MB-9).

   subtype Octet is Natural range 0 .. 255;

   type Address_Kind is (Address_Broadcast, Address_Unicast, Address_Reserved);

   function Address_Class (A : Octet) return Address_Kind is
     (if A = 0 then Address_Broadcast
      elsif A <= 247 then Address_Unicast
      else Address_Reserved)
     with Post => (Address_Class'Result = Address_Broadcast) = (A = 0)
                  and then (Address_Class'Result = Address_Unicast) = (A >= 1 and then A <= 247)
                  and then (Address_Class'Result = Address_Reserved) = (A >= 248);

   function Rtu_Pdu_Length (N : Natural) return Natural is
     (N - 3)
     with Pre  => N >= 4 and then N <= 256,
          Post => Rtu_Pdu_Length'Result >= 1 and then Rtu_Pdu_Length'Result <= 253;

   function Rtu_Verdict
     (N        : Natural;
      Address  : Octet;
      Computed : Lovelace_Mb_Crc_Wire_Pkg.Crc_Number;
      Lo, Hi   : Lovelace_Mb_Crc_Wire_Pkg.Wire_Byte)
      return Lovelace_Mb_Frame_Refusal_Pkg.Frame_Verdict is
     (if N < 4 then Lovelace_Mb_Frame_Refusal_Pkg.Short_Adu
      elsif N > 256 then Lovelace_Mb_Frame_Refusal_Pkg.Long_Adu
      elsif not Lovelace_Mb_Crc_Wire_Pkg.Crc_Matches (Computed, Lo, Hi)
      then Lovelace_Mb_Frame_Refusal_Pkg.Bad_Crc
      elsif Address_Class (Address) = Address_Reserved
      then Lovelace_Mb_Frame_Refusal_Pkg.Reserved_Address
      else Lovelace_Mb_Frame_Refusal_Pkg.Frame_Ok)
     with Post => (if Rtu_Verdict'Result = Lovelace_Mb_Frame_Refusal_Pkg.Frame_Ok
                   then Lovelace_Mb_Crc_Wire_Pkg.Crc_Matches (Computed, Lo, Hi)
                        and then Computed = Lovelace_Mb_Crc_Wire_Pkg.Wire_Value (Lo, Hi)
                        and then N >= 4 and then N <= 256
                        and then Rtu_Pdu_Length (N) >= 1 and then Rtu_Pdu_Length (N) <= 253
                        and then Address <= 247)
                  and then (if not Lovelace_Mb_Crc_Wire_Pkg.Crc_Matches (Computed, Lo, Hi)
                            then Rtu_Verdict'Result /= Lovelace_Mb_Frame_Refusal_Pkg.Frame_Ok)
                  and then (if N >= 4 and then N <= 256
                              and then Lovelace_Mb_Crc_Wire_Pkg.Crc_Matches (Computed, Lo, Hi)
                              and then Address <= 247
                            then Rtu_Verdict'Result = Lovelace_Mb_Frame_Refusal_Pkg.Frame_Ok);

end Lovelace_Mb_Rtu_Accept_Pkg;
