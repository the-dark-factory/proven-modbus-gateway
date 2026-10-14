with Lovelace_Mb_Pdu_Fields_Pkg;
with Lovelace_Mb_Addr_Span_Pkg;
with Lovelace_Mb_Fc_Catalog_Pkg;
with Lovelace_Mb_Pdu_Dispatch_Pkg;
with Lovelace_Mb_Pdu_View_Pkg;
with Lovelace_Mb_Policy_Shape_Pkg;

package Lovelace_Mb_Write_Effect_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind;
   use type Lovelace_Mb_Policy_Shape_Pkg.Write_Target;

   --  The write footprint of a request PDU P (1 .. N) the dispatcher judged Pdu_Ok, in the
   --  terms of the wave-3 policy cores: Target_Of (coils for FC5 and FC15, holding registers
   --  for FC6, FC16, FC22 and FC23 [APP s.6.5, s.6.6, s.6.11, s.6.12, s.6.16, s.6.17]),
   --  Write_Start, Write_Qty (1 .. 1968, the span fits) and Values_Of, the written values as
   --  one Written_Values array (element K for address Write_Start + K - 1, K = 1 .. Write_Qty;
   --  a coil as 0 or 1; every element past Write_Qty is 0). Reads (FC1-4) and FC43/14 write
   --  nothing, so they never meet a write rule. FC22 carries masks, not values: its result
   --  depends on the register's current contents [APP s.6.16], so Values_Of holds 0 for it
   --  and the gate refuses FC22 on any register a value or sequence rule names (R-MB-13,
   --  R-MB-30).

   function Writes_Anything (P : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes) return Boolean is
     (Lovelace_Mb_Fc_Catalog_Pkg.Is_Write_Kind (Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P)))
     with Post => Writes_Anything'Result
                    = (Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) not in Lovelace_Mb_Fc_Catalog_Pkg.Read_Bits_Kind
                       and then Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) not in Lovelace_Mb_Fc_Catalog_Pkg.Read_Words_Kind
                       and then Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) /= Lovelace_Mb_Fc_Catalog_Pkg.Encapsulated_Fc
                       and then Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) /= Lovelace_Mb_Fc_Catalog_Pkg.Unsupported_Fc);

   function Target_Of (P : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes) return Lovelace_Mb_Policy_Shape_Pkg.Write_Target is
     (if Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Write_Coil_Fc
         or else Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Write_Coils_Fc
      then Lovelace_Mb_Policy_Shape_Pkg.Coil_Target
      else Lovelace_Mb_Policy_Shape_Pkg.Register_Target)
     with Pre => Writes_Anything (P),
          Post => (Target_Of'Result = Lovelace_Mb_Policy_Shape_Pkg.Coil_Target)
                    = (P (1) = 5 or else P (1) = 15);

   function Write_Start
     (P : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes;
      N : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length) return Lovelace_Mb_Policy_Shape_Pkg.Item_Address is
     (Lovelace_Mb_Pdu_View_Pkg.Write_Start_Of (P, N))
     with Pre => Lovelace_Mb_Pdu_Dispatch_Pkg.Request_Ok (P, N) and then Writes_Anything (P);

   function Write_Qty
     (P : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes;
      N : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length) return Lovelace_Mb_Policy_Shape_Pkg.Write_Quantity is
     (Lovelace_Mb_Pdu_View_Pkg.Write_Qty_Of (P, N))
     with Pre => Lovelace_Mb_Pdu_Dispatch_Pkg.Request_Ok (P, N) and then Writes_Anything (P),
          Post => Write_Qty'Result <= 65_536 - Write_Start (P, N)
                  and then Lovelace_Mb_Addr_Span_Pkg.Span_Ok (Write_Start (P, N), Write_Qty'Result)
                  and then (if P (1) = 5 or else P (1) = 6 or else P (1) = 22 then Write_Qty'Result = 1);

   function Values_Of
     (P : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes;
      N : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length) return Lovelace_Mb_Policy_Shape_Pkg.Written_Values is
     ((for K in Lovelace_Mb_Policy_Shape_Pkg.Write_Quantity =>
         (if K <= Write_Qty (P, N) and then Lovelace_Mb_Pdu_View_Pkg.Has_Written_Values (P)
          then Lovelace_Mb_Pdu_View_Pkg.Written_Value (P, N, K)
          else 0)))
     with Pre => Lovelace_Mb_Pdu_Dispatch_Pkg.Request_Ok (P, N) and then Writes_Anything (P),
          Post => (for all K in 1 .. Write_Qty (P, N) =>
                     (if Lovelace_Mb_Pdu_View_Pkg.Has_Written_Values (P)
                      then Values_Of'Result (K) = Lovelace_Mb_Pdu_View_Pkg.Written_Value (P, N, K)
                      else Values_Of'Result (K) = 0))
                  and then (for all K in Lovelace_Mb_Policy_Shape_Pkg.Write_Quantity =>
                              (if K > Write_Qty (P, N) then Values_Of'Result (K) = 0))
                  and then (if Target_Of (P) = Lovelace_Mb_Policy_Shape_Pkg.Coil_Target
                            then (for all K in Lovelace_Mb_Policy_Shape_Pkg.Write_Quantity =>
                                    Values_Of'Result (K) <= 1));

end Lovelace_Mb_Write_Effect_Pkg;
