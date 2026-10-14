with Lovelace_Mb_Pdu_Fields_Pkg;
with Lovelace_Mb_Addr_Span_Pkg;
with Lovelace_Mb_Fc_Catalog_Pkg;
with Lovelace_Mb_Pdu_Dispatch_Pkg;

package Lovelace_Mb_Pdu_View_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind;

   --  The parsed view of a request PDU P (1 .. N) that the dispatcher judged Pdu_Ok
   --  (Lovelace_Mb_Pdu_Dispatch_Pkg.Request_Ok). Every accessor's Pre holds whenever Request_Ok
   --  holds (and the code is one the accessor names); every field is read through Byte_At /
   --  Word_At, whose Pres the dispatcher's verdict has already established. Wave 3 builds its
   --  write policy on Write_Start_Of, Write_Qty_Of (1 .. 1968, the span fits) and Written_Value
   --  (K in 1 .. Write_Qty_Of). Fields [APP s.4.2] are big-endian; FC15 coils [APP s.6.11] are
   --  packed least significant bit first; FC16 values follow the 6-byte head, FC23 values the
   --  10-byte head, two bytes each [APP s.6.12, s.6.17]. The three Spec_Example functions are the
   --  spec's own examples, so the offsets and the bit order are proved, not assumed.

   subtype Bit is Natural range 0 .. 1;
   subtype Bit_Index is Natural range 0 .. 7;

   --  The Starting Address of a Pdu_Ok request (FC23: the Read Starting Address).
   function Start_Of
     (P : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes;
      N : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length) return Lovelace_Mb_Pdu_Fields_Pkg.Word is
     (Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 2))
     with Pre => Lovelace_Mb_Pdu_Dispatch_Pkg.Request_Ok (P, N)
                 and then Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) /= Lovelace_Mb_Fc_Catalog_Pkg.Encapsulated_Fc;

   --  The number of items a Pdu_Ok request names: its Quantity (FC23: the Quantity to Read);
   --  1 for FC5, FC6 and FC22.
   function Quantity_Of
     (P : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes;
      N : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length) return Lovelace_Mb_Pdu_Fields_Pkg.Word is
     (case Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) is
         when Lovelace_Mb_Fc_Catalog_Pkg.Single_Write_Kind | Lovelace_Mb_Fc_Catalog_Pkg.Mask_Write_Fc => 1,
         when others => Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 4))
     with Pre => Lovelace_Mb_Pdu_Dispatch_Pkg.Request_Ok (P, N)
                 and then Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) /= Lovelace_Mb_Fc_Catalog_Pkg.Encapsulated_Fc,
          Post => Quantity_Of'Result >= 1 and then Quantity_Of'Result <= 2_000
                  and then Start_Of (P, N) + Quantity_Of'Result <= 65_536
                  and then Lovelace_Mb_Addr_Span_Pkg.Span_Ok (Start_Of (P, N), Quantity_Of'Result)
                  and then (if Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) in Lovelace_Mb_Fc_Catalog_Pkg.Read_Words_Kind
                               or else Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Read_Write_Fc
                            then Quantity_Of'Result <= 125);

   --  The first address a Pdu_Ok write request writes (FC23: the Write Starting Address).
   function Write_Start_Of
     (P : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes;
      N : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length) return Lovelace_Mb_Pdu_Fields_Pkg.Word is
     (if Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Read_Write_Fc
      then Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 6)
      else Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 2))
     with Pre => Lovelace_Mb_Pdu_Dispatch_Pkg.Request_Ok (P, N)
                 and then Lovelace_Mb_Fc_Catalog_Pkg.Is_Write_Kind (Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P));

   --  How many items a Pdu_Ok write request writes: 1 for FC5, FC6 and FC22; the Quantity
   --  for FC15 and FC16; the Quantity to Write for FC23.
   function Write_Qty_Of
     (P : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes;
      N : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length) return Lovelace_Mb_Pdu_Fields_Pkg.Word is
     (case Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) is
         when Lovelace_Mb_Fc_Catalog_Pkg.Write_Coils_Fc | Lovelace_Mb_Fc_Catalog_Pkg.Write_Registers_Fc =>
           Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 4),
         when Lovelace_Mb_Fc_Catalog_Pkg.Read_Write_Fc => Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 8),
         when others => 1)
     with Pre => Lovelace_Mb_Pdu_Dispatch_Pkg.Request_Ok (P, N)
                 and then Lovelace_Mb_Fc_Catalog_Pkg.Is_Write_Kind (Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P)),
          Post => Write_Qty_Of'Result >= 1 and then Write_Qty_Of'Result <= 1_968
                  and then Write_Start_Of (P, N) + Write_Qty_Of'Result <= 65_536
                  and then Lovelace_Mb_Addr_Span_Pkg.Span_Ok (Write_Start_Of (P, N), Write_Qty_Of'Result)
                  and then (if Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Write_Coils_Fc
                            then 8 * (N - 6) >= Write_Qty_Of'Result)
                  and then (if Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Write_Registers_Fc
                            then N - 6 = 2 * Write_Qty_Of'Result)
                  and then (if Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Read_Write_Fc
                            then N - 10 = 2 * Write_Qty_Of'Result)
                  and then (if Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) in Lovelace_Mb_Fc_Catalog_Pkg.Single_Write_Kind
                               or else Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Mask_Write_Fc
                            then Write_Qty_Of'Result = 1);

   --  A write whose values are in the request: every write code but FC22, whose result
   --  depends on the register's current contents [APP s.6.16].
   function Has_Written_Values (P : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes) return Boolean is
     (Lovelace_Mb_Fc_Catalog_Pkg.Is_Write_Kind (Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P))
      and then Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) /= Lovelace_Mb_Fc_Catalog_Pkg.Mask_Write_Fc);

   function Bit_Weight (I : Bit_Index) return Positive is
     (case I is
         when 0 => 1,
         when 1 => 2,
         when 2 => 4,
         when 3 => 8,
         when 4 => 16,
         when 5 => 32,
         when 6 => 64,
         when 7 => 128)
     with Post => Bit_Weight'Result <= 128;

   --  [APP s.6.11]: in each output byte "the least significant bit addressing the lowest output".
   function Coil_Bit (B : Lovelace_Mb_Pdu_Fields_Pkg.Octet; I : Bit_Index) return Bit is
     ((B / Bit_Weight (I)) mod 2);

   --  The K-th value a Pdu_Ok request writes, K in 1 .. Write_Qty_Of: a coil as 0 (OFF) or 1 (ON)
   --  (FC5: 16#FF00# is ON; FC15: bit (K - 1) mod 8 of output byte (K - 1) / 8, least significant
   --  first); a register value as the word (FC6: the value; FC16 and FC23: the K-th register
   --  value, big-endian, after the head).
   function Written_Value
     (P : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes;
      N : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length;
      K : Positive) return Lovelace_Mb_Pdu_Fields_Pkg.Word is
     (case Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) is
         when Lovelace_Mb_Fc_Catalog_Pkg.Write_Coil_Fc =>
           (if Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 4) = 16#FF00# then 1 else 0),
         when Lovelace_Mb_Fc_Catalog_Pkg.Write_Register_Fc => Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 4),
         when Lovelace_Mb_Fc_Catalog_Pkg.Write_Coils_Fc =>
           Coil_Bit (Lovelace_Mb_Pdu_Fields_Pkg.Byte_At (P, N, 7 + (K - 1) / 8), (K - 1) mod 8),
         when Lovelace_Mb_Fc_Catalog_Pkg.Write_Registers_Fc => Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 5 + 2 * K),
         when Lovelace_Mb_Fc_Catalog_Pkg.Read_Write_Fc => Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 9 + 2 * K),
         when others => 0)
     with Pre => Lovelace_Mb_Pdu_Dispatch_Pkg.Request_Ok (P, N)
                 and then Has_Written_Values (P) and then K <= Write_Qty_Of (P, N),
          Post => (if Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Write_Coil_Fc
                      or else Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Write_Coils_Fc
                   then Written_Value'Result <= 1);

   --  The [APP s.6.11] example: write 10 coils from coil 20 (16#13#), outputs CD 01 hex.
   function Spec_Example_Fc15 return Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes is
     ((1 => 16#0F#, 2 => 16#00#, 3 => 16#13#, 4 => 16#00#, 5 => 16#0A#, 6 => 16#02#,
       7 => 16#CD#, 8 => 16#01#, others => 0))
     with Post => Lovelace_Mb_Pdu_Dispatch_Pkg.Request_Ok (Spec_Example_Fc15'Result, 8)
                  and then Write_Start_Of (Spec_Example_Fc15'Result, 8) = 19
                  and then Write_Qty_Of (Spec_Example_Fc15'Result, 8) = 10
                  and then Written_Value (Spec_Example_Fc15'Result, 8, 1) = 1
                  and then Written_Value (Spec_Example_Fc15'Result, 8, 2) = 0
                  and then Written_Value (Spec_Example_Fc15'Result, 8, 8) = 1
                  and then Written_Value (Spec_Example_Fc15'Result, 8, 9) = 1
                  and then Written_Value (Spec_Example_Fc15'Result, 8, 10) = 0;

   --  The [APP s.6.12] example: write 2 registers from register 2 (address 1): 00 0A and 01 02 hex.
   function Spec_Example_Fc16 return Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes is
     ((1 => 16#10#, 2 => 16#00#, 3 => 16#01#, 4 => 16#00#, 5 => 16#02#, 6 => 16#04#,
       7 => 16#00#, 8 => 16#0A#, 9 => 16#01#, 10 => 16#02#, others => 0))
     with Post => Lovelace_Mb_Pdu_Dispatch_Pkg.Request_Ok (Spec_Example_Fc16'Result, 10)
                  and then Write_Start_Of (Spec_Example_Fc16'Result, 10) = 1
                  and then Write_Qty_Of (Spec_Example_Fc16'Result, 10) = 2
                  and then Written_Value (Spec_Example_Fc16'Result, 10, 1) = 16#000A#
                  and then Written_Value (Spec_Example_Fc16'Result, 10, 2) = 16#0102#;

   --  The [APP s.6.17] example: read 6 registers from address 3, write 3 registers from
   --  address 14 (16#0E#), each 00 FF hex.
   function Spec_Example_Fc23 return Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes is
     ((1 => 16#17#, 2 => 16#00#, 3 => 16#03#, 4 => 16#00#, 5 => 16#06#, 6 => 16#00#, 7 => 16#0E#,
       8 => 16#00#, 9 => 16#03#, 10 => 16#06#, 11 => 16#00#, 12 => 16#FF#, 13 => 16#00#, 14 => 16#FF#,
       15 => 16#00#, 16 => 16#FF#, others => 0))
     with Post => Lovelace_Mb_Pdu_Dispatch_Pkg.Request_Ok (Spec_Example_Fc23'Result, 16)
                  and then Start_Of (Spec_Example_Fc23'Result, 16) = 3
                  and then Quantity_Of (Spec_Example_Fc23'Result, 16) = 6
                  and then Write_Start_Of (Spec_Example_Fc23'Result, 16) = 14
                  and then Write_Qty_Of (Spec_Example_Fc23'Result, 16) = 3
                  and then Written_Value (Spec_Example_Fc23'Result, 16, 1) = 16#00FF#
                  and then Written_Value (Spec_Example_Fc23'Result, 16, 3) = 16#00FF#;
end Lovelace_Mb_Pdu_View_Pkg;
