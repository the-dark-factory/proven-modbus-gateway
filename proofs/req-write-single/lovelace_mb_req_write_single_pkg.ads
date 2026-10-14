with Lovelace_Mb_Pdu_Refusal_Pkg;
with Lovelace_Mb_Pdu_Fields_Pkg;
with Lovelace_Mb_Fc_Catalog_Pkg;

package Lovelace_Mb_Req_Write_Single_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict;
   use type Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind;

   --  FC5 Write Single Coil [APP s.6.5] and FC6 Write Single Register [APP s.6.6] requests:
   --  function code, Address (2 bytes, 16#0000# to 16#FFFF#), Value (2 bytes), so N = 5 bytes.
   --  FC5: "A value of FF 00 hex requests the output to be ON. A value of 00 00 requests it
   --  to be OFF. All other values are illegal" -> 03 (Figure 15 tests the value before the
   --  address). FC6: every value 16#0000# to 16#FFFF# is legal at this layer (value limits
   --  are the site policy's, wave 3). The address is never refused here: a one-item span is
   --  always OK (the address-span core, R-MB-8), so neither code gives Address_Overflow.
   --  A PDU length other than 5 is 03 ("the implied length is incorrect" [APP s.7]).

   function Write_Single_Verdict
     (Kind  : Lovelace_Mb_Fc_Catalog_Pkg.Single_Write_Kind;
      N     : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length;
      Value : Lovelace_Mb_Pdu_Fields_Pkg.Word) return Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict is
     (if N /= 5 then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
      elsif Kind = Lovelace_Mb_Fc_Catalog_Pkg.Write_Coil_Fc
        and then Value /= 16#0000# and then Value /= 16#FF00#
      then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Coil_Value
      else Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
     with Post => (Write_Single_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
                    = (N = 5
                       and then (Kind = Lovelace_Mb_Fc_Catalog_Pkg.Write_Register_Fc
                                 or else Value = 16#0000# or else Value = 16#FF00#))
                  and then (if N /= 5
                            then Write_Single_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length)
                  and then (if N = 5 and then Kind = Lovelace_Mb_Fc_Catalog_Pkg.Write_Coil_Fc
                               and then (Value = 16#00FF# or else Value = 16#FFFF#)
                            then Write_Single_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Coil_Value)
                  and then (if N = 5 and then Kind = Lovelace_Mb_Fc_Catalog_Pkg.Write_Register_Fc
                            then Write_Single_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
                  and then Write_Single_Verdict'Result /= Lovelace_Mb_Pdu_Refusal_Pkg.Address_Overflow;

   function Coil_On (Value : Lovelace_Mb_Pdu_Fields_Pkg.Word) return Boolean is
     (Value = 16#FF00#);

end Lovelace_Mb_Req_Write_Single_Pkg;
