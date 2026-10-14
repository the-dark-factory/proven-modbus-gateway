package Lovelace_Mb_Pdu_Fields_Pkg with SPARK_Mode, Pure is

   --  The PDU as received and its fields, from the public Modbus specification.
   --  [APP s.4.1]: a PDU is 1 .. 253 bytes, function code first (R-MB-4).
   --  [APP s.4.2]: addresses and data items are big-endian, the most significant byte first.
   --  A field is read only after Field_Present has checked that its bytes lie inside the
   --  N bytes received (subtract-first: Width <= N - Offset + 1).
   --  [APP s.6.1, s.6.11]: N* = quantity / 8, plus 1 when the remainder is not 0 (Bits_Bytes);
   --  [APP s.6.3, s.6.12]: 2 x N bytes for N registers (Word_Bytes).

   subtype Octet is Natural range 0 .. 255;
   subtype Word is Natural range 0 .. 65_535;
   subtype Pdu_Length is Natural range 1 .. 253;
   subtype Pdu_Index is Positive range 1 .. 253;
   subtype Field_Width is Positive range 1 .. 253;
   subtype Item_Quantity is Natural range 0 .. 2_000;

   type Pdu_Bytes is array (Pdu_Index) of Octet;

   function Field_Present (N : Pdu_Length; Offset : Pdu_Index; Width : Field_Width) return Boolean is
     (Width <= N - Offset + 1)
     with Post => Field_Present'Result = (Offset + Width - 1 <= N);

   function Byte_At (P : Pdu_Bytes; N : Pdu_Length; Offset : Pdu_Index) return Octet is
     (P (Offset))
     with Pre => Field_Present (N, Offset, 1);

   function Word_At (P : Pdu_Bytes; N : Pdu_Length; Offset : Pdu_Index) return Word is
     (P (Offset) * 256 + P (Offset + 1))
     with Pre => Field_Present (N, Offset, 2),
          Post => Word_At'Result / 256 = P (Offset)
                  and then Word_At'Result mod 256 = P (Offset + 1);

   function Bits_Bytes (Q : Item_Quantity) return Natural is
     ((Q + 7) / 8)
     with Post => 8 * Bits_Bytes'Result >= Q
                  and then 8 * Bits_Bytes'Result < Q + 8
                  and then Bits_Bytes'Result <= 250;

   function Word_Bytes (Q : Item_Quantity) return Natural is
     (2 * Q)
     with Post => Word_Bytes'Result mod 2 = 0
                  and then Word_Bytes'Result / 2 = Q
                  and then Word_Bytes'Result <= 4_000;

   function Data_Present (N : Pdu_Length; Header : Field_Width; Byte_Count : Octet) return Boolean is
     (Byte_Count = N - Header)
     with Post => Data_Present'Result = (Header + Byte_Count = N);

end Lovelace_Mb_Pdu_Fields_Pkg;
