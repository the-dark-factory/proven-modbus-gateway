with Lovelace_Mb_Pdu_Refusal_Pkg;
with Lovelace_Mb_Pdu_Fields_Pkg;

package Lovelace_Mb_Req_Mask_Write_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict;

   --  FC22 Mask Write Register requests [APP s.6.16]: function code, Reference Address,
   --  And_Mask and Or_Mask (2 bytes each, 16#0000# to 16#FFFF#), so N = 7 bytes. Every
   --  address and every mask is legal at this layer: a one-item span is always OK
   --  (the address-span core, R-MB-8). A PDU length other than 7 is 03 ([APP s.7]).
   --  The function's algorithm [APP s.6.16]:
   --    Result = (Current Contents AND And_Mask) OR (Or_Mask AND (NOT And_Mask))
   --  on 16-bit words. The spec's example: Current 16#12#, And_Mask 16#F2#, Or_Mask 16#25#
   --  give 16#17#. If And_Mask is 16#FFFF# the register is unchanged; if it is 0 the result
   --  is Or_Mask; if Or_Mask is 0 the result is Current AND And_Mask.
   --  The gateway cannot know Current, so wave 3 refuses FC22 on a limited register (R-MB-13).
   --  The `and`, `or` and `not` in Mask_Result are the bitwise operators of Mask_Word.

   type Mask_Word is mod 2 ** 16;

   function Mask_Write_Verdict
     (N : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length) return Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict is
     (if N /= 7 then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
      else Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
     with Post => (Mask_Write_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok) = (N = 7)
                  and then (if N /= 7
                            then Mask_Write_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length);

   function To_Mask (W : Lovelace_Mb_Pdu_Fields_Pkg.Word) return Mask_Word is
     (Mask_Word (W))
     with Post => Natural (To_Mask'Result) = W;

   function From_Mask (M : Mask_Word) return Lovelace_Mb_Pdu_Fields_Pkg.Word is
     (Natural (M))
     with Post => To_Mask (From_Mask'Result) = M;

   function Mask_Result (Current, And_Mask, Or_Mask : Mask_Word) return Mask_Word is
     ((Current and And_Mask) or (Or_Mask and (not And_Mask)))
     with Post => (if And_Mask = 16#FFFF# then Mask_Result'Result = Current)
                  and then (if And_Mask = 0 then Mask_Result'Result = Or_Mask)
                  and then (if Or_Mask = 0 then Mask_Result'Result = (Current and And_Mask))
                  and then (Mask_Result'Result and And_Mask) = (Current and And_Mask)
                  and then (Mask_Result'Result and (not And_Mask)) = (Or_Mask and (not And_Mask));

   function Spec_Example_Result return Mask_Word is
     (Mask_Result (16#12#, 16#F2#, 16#25#))
     with Post => Spec_Example_Result'Result = 16#17#;

end Lovelace_Mb_Req_Mask_Write_Pkg;
