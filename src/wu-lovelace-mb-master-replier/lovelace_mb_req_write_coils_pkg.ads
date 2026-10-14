with Lovelace_Mb_Pdu_Refusal_Pkg;
with Lovelace_Mb_Pdu_Fields_Pkg;
with Lovelace_Mb_Addr_Span_Pkg;

package Lovelace_Mb_Req_Write_Coils_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict;

   --  FC15 Write Multiple Coils requests [APP s.6.11]: function code, Starting Address
   --  (2 bytes, 16#0000# to 16#FFFF#), Quantity of Outputs (2 bytes, 1 to 1968, 16#07B0#),
   --  Byte Count (1 byte, N*) and N* bytes of output values, where
   --  "N* = Quantity of Outputs / 8, if the remainder is different of 0 N* = N* + 1".
   --  So the head is 6 bytes and the PDU is exactly 6 + Byte Count bytes.
   --  Tested in the order of the state diagram (Figure 21): a PDU shorter than its 6-byte head
   --  (03, "the implied length is incorrect" [APP s.7]); the quantity (03); the byte count,
   --  which must equal N* AND the bytes that follow the head (03); then Starting Address +
   --  Quantity of Outputs (02, R-MB-8); else Pdu_Ok. Both the quantity and the byte count
   --  are tested before any output byte is read. The unused bits of the last output byte
   --  "should be zero-filled"; they are not judged (R-MB-11), so no output byte is a parameter.

   function Write_Coils_Verdict
     (N          : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length;
      Start      : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Quantity   : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Byte_Count : Lovelace_Mb_Pdu_Fields_Pkg.Octet) return Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict is
     (if N < 6 then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
      elsif Quantity < 1 or else Quantity > 16#07B0# then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Quantity
      elsif Byte_Count /= Lovelace_Mb_Pdu_Fields_Pkg.Bits_Bytes (Quantity)
        or else not Lovelace_Mb_Pdu_Fields_Pkg.Data_Present (N, 6, Byte_Count)
      then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Byte_Count
      elsif not Lovelace_Mb_Addr_Span_Pkg.Span_Ok (Start, Quantity)
      then Lovelace_Mb_Pdu_Refusal_Pkg.Address_Overflow
      else Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
     with Post => (Write_Coils_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
                    = (N >= 6 and then Quantity >= 1 and then Quantity <= 1_968
                       and then Byte_Count = Quantity / 8 + (if Quantity mod 8 = 0 then 0 else 1)
                       and then N = 6 + Byte_Count
                       and then Start + Quantity <= 65_536)
                  and then (if Write_Coils_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok
                            then N <= 252 and then 8 * (N - 6) >= Quantity)
                  and then (if N < 6
                            then Write_Coils_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length)
                  and then (if N >= 6 and then (Quantity < 1 or else Quantity > 1_968)
                            then Write_Coils_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Quantity)
                  and then (if N >= 6 and then Quantity >= 1 and then Quantity <= 1_968
                               and then (8 * Byte_Count < Quantity or else 8 * Byte_Count >= Quantity + 8
                                         or else N /= 6 + Byte_Count)
                            then Write_Coils_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Byte_Count)
                  and then (if N >= 6 and then Quantity >= 1 and then Quantity <= 1_968
                               and then Byte_Count = (Quantity + 7) / 8 and then N = 6 + Byte_Count
                               and then Start + Quantity > 65_536
                            then Write_Coils_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Address_Overflow);

end Lovelace_Mb_Req_Write_Coils_Pkg;
