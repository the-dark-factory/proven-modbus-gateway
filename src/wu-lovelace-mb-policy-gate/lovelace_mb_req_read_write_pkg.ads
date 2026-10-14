with Lovelace_Mb_Pdu_Refusal_Pkg;
with Lovelace_Mb_Pdu_Fields_Pkg;
with Lovelace_Mb_Addr_Span_Pkg;

package Lovelace_Mb_Req_Read_Write_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict;

   --  FC23 Read/Write Multiple Registers requests [APP s.6.17]: function code, Read Starting
   --  Address (2 bytes), Quantity to Read (2 bytes, 1 to 125, 16#007D#), Write Starting
   --  Address (2 bytes), Quantity to Write (2 bytes, 1 to 121, 16#0079#), Write Byte Count
   --  (1 byte, 2 x N*) and N* x 2 bytes of register values, N* = Quantity to Write.
   --  So the head is 10 bytes and the PDU is exactly 10 + Write Byte Count bytes.
   --  Tested in the order of the state diagram (Figure 27): a PDU shorter than its 10-byte
   --  head (03, "the implied length is incorrect" [APP s.7]); both quantities (03); "Byte
   --  Count == Quantity of Write x 2", and the byte count must also equal the bytes that
   --  follow the head (03); then both Starting Address + Quantity rules, read and write
   --  (02, R-MB-8); else Pdu_Ok. Both quantities and the byte count are tested before any
   --  write value is read. "The write operation is performed before the read."

   function Read_Write_Verdict
     (N              : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length;
      Read_Start     : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Read_Quantity  : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Write_Start    : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Write_Quantity : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Byte_Count     : Lovelace_Mb_Pdu_Fields_Pkg.Octet) return Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict is
     (if N < 10 then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
      elsif Read_Quantity < 1 or else Read_Quantity > 16#007D#
        or else Write_Quantity < 1 or else Write_Quantity > 16#0079#
      then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Quantity
      elsif Byte_Count /= Lovelace_Mb_Pdu_Fields_Pkg.Word_Bytes (Write_Quantity)
        or else not Lovelace_Mb_Pdu_Fields_Pkg.Data_Present (N, 10, Byte_Count)
      then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Byte_Count
      elsif not Lovelace_Mb_Addr_Span_Pkg.Span_Ok (Read_Start, Read_Quantity)
        or else not Lovelace_Mb_Addr_Span_Pkg.Span_Ok (Write_Start, Write_Quantity)
      then Lovelace_Mb_Pdu_Refusal_Pkg.Address_Overflow
      else Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
     with Post => (Read_Write_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
                    = (N >= 10 and then Read_Quantity >= 1 and then Read_Quantity <= 125
                       and then Write_Quantity >= 1 and then Write_Quantity <= 121
                       and then Byte_Count = 2 * Write_Quantity
                       and then N = 10 + Byte_Count
                       and then Read_Start + Read_Quantity <= 65_536
                       and then Write_Start + Write_Quantity <= 65_536)
                  and then (if Read_Write_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok
                            then N <= 252 and then N - 10 = 2 * Write_Quantity)
                  and then (if N < 10
                            then Read_Write_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length)
                  and then (if N >= 10
                               and then (Read_Quantity < 1 or else Read_Quantity > 125
                                         or else Write_Quantity < 1 or else Write_Quantity > 121)
                            then Read_Write_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Quantity)
                  and then (if N >= 10 and then Read_Quantity >= 1 and then Read_Quantity <= 125
                               and then Write_Quantity >= 1 and then Write_Quantity <= 121
                               and then (Byte_Count /= 2 * Write_Quantity or else N /= 10 + Byte_Count)
                            then Read_Write_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Byte_Count)
                  and then (if N >= 10 and then Read_Quantity >= 1 and then Read_Quantity <= 125
                               and then Write_Quantity >= 1 and then Write_Quantity <= 121
                               and then Byte_Count = 2 * Write_Quantity and then N = 10 + Byte_Count
                               and then (Read_Start + Read_Quantity > 65_536
                                         or else Write_Start + Write_Quantity > 65_536)
                            then Read_Write_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Address_Overflow);

end Lovelace_Mb_Req_Read_Write_Pkg;
