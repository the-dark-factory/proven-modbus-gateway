with Lovelace_Mb_Pdu_Refusal_Pkg;
with Lovelace_Mb_Pdu_Fields_Pkg;
with Lovelace_Mb_Addr_Span_Pkg;

package Lovelace_Mb_Req_Write_Registers_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict;

   --  FC16 Write Multiple Registers requests [APP s.6.12]: function code, Starting Address
   --  (2 bytes, 16#0000# to 16#FFFF#), Quantity of Registers (2 bytes, 1 to 123, 16#007B#),
   --  Byte Count (1 byte, 2 x N*) and N* x 2 bytes of register values, N* = Quantity of
   --  Registers. So the head is 6 bytes and the PDU is exactly 6 + Byte Count bytes.
   --  Tested in the order of the state diagram (Figure 22): a PDU shorter than its 6-byte head
   --  (03, "the implied length is incorrect" [APP s.7]); the quantity (03); "Byte Count ==
   --  Quantity of Registers x 2", and the byte count must also equal the bytes that follow
   --  the head (03); then Starting Address + Quantity of Registers (02, R-MB-8); else Pdu_Ok.
   --  Both the quantity and the byte count are tested before any register value is read.
   --  An odd byte count is never 2 x N*, so it is always Bad_Byte_Count.

   function Write_Registers_Verdict
     (N          : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length;
      Start      : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Quantity   : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Byte_Count : Lovelace_Mb_Pdu_Fields_Pkg.Octet) return Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict is
     (if N < 6 then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
      elsif Quantity < 1 or else Quantity > 16#007B# then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Quantity
      elsif Byte_Count /= Lovelace_Mb_Pdu_Fields_Pkg.Word_Bytes (Quantity)
        or else not Lovelace_Mb_Pdu_Fields_Pkg.Data_Present (N, 6, Byte_Count)
      then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Byte_Count
      elsif not Lovelace_Mb_Addr_Span_Pkg.Span_Ok (Start, Quantity)
      then Lovelace_Mb_Pdu_Refusal_Pkg.Address_Overflow
      else Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
     with Post => (Write_Registers_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
                    = (N >= 6 and then Quantity >= 1 and then Quantity <= 123
                       and then Byte_Count = 2 * Quantity
                       and then N = 6 + Byte_Count
                       and then Start + Quantity <= 65_536)
                  and then (if Write_Registers_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok
                            then N <= 252 and then N - 6 = 2 * Quantity)
                  and then (if N < 6
                            then Write_Registers_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length)
                  and then (if N >= 6 and then (Quantity < 1 or else Quantity > 123)
                            then Write_Registers_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Quantity)
                  and then (if N >= 6 and then Quantity >= 1 and then Quantity <= 123
                               and then (Byte_Count /= 2 * Quantity or else N /= 6 + Byte_Count)
                            then Write_Registers_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Byte_Count)
                  and then (if N >= 6 and then Quantity >= 1 and then Quantity <= 123
                               and then Byte_Count mod 2 = 1
                            then Write_Registers_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Byte_Count)
                  and then (if N >= 6 and then Quantity >= 1 and then Quantity <= 123
                               and then Byte_Count = 2 * Quantity and then N = 6 + Byte_Count
                               and then Start + Quantity > 65_536
                            then Write_Registers_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Address_Overflow);

end Lovelace_Mb_Req_Write_Registers_Pkg;
