package Lovelace_Mb_Addr_Span_Pkg with SPARK_Mode, Pure is

   --  The one address rule the public Modbus specification fixes for every server (R-MB-8):
   --  [APP s.6.1 - s.6.4, s.6.11, s.6.12, s.6.17] state diagrams: "Starting Address + Quantity"
   --  must be OK, else exception 02; [APP s.7] code 02: "the combination of reference number
   --  and transfer length is invalid". Addresses are 0 .. 65535 (16#0000# to 16#FFFF#), so a
   --  span is OK exactly when Start + Quantity <= 65536. Tested subtract-first, so no sum is
   --  formed: Quantity <= 65536 - Start.
   --  A one-item span (FC5, FC6, FC22) is always OK: those codes never give Address_Overflow.

   subtype Address is Natural range 0 .. 65_535;
   subtype Span_Quantity is Natural range 1 .. 2_000;

   function Span_Ok (Start : Address; Quantity : Span_Quantity) return Boolean is
     (Quantity <= 65_536 - Start)
     with Post => Span_Ok'Result = (Start + Quantity <= 65_536)
                  and then (if Quantity = 1 then Span_Ok'Result);

   function Last_Address (Start : Address; Quantity : Span_Quantity) return Address is
     (Start + (Quantity - 1))
     with Pre => Span_Ok (Start, Quantity),
          Post => Last_Address'Result >= Start
                  and then Last_Address'Result - Start = Quantity - 1;

end Lovelace_Mb_Addr_Span_Pkg;
