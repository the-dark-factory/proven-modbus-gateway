with Lovelace_Mb_Pdu_Refusal_Pkg;
with Lovelace_Mb_Pdu_Fields_Pkg;
with Lovelace_Mb_Fc_Catalog_Pkg;

package Lovelace_Mb_Resp_Echo_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict;
   use type Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind;

   --  The normal reply to a write request, checked against the request that caused it.
   --  [APP s.6.5] FC5 and [APP s.6.6] FC6: "The normal response is an echo of the request":
   --  function code, address, value -- 5 bytes; F1 = address, F2 = value.
   --  [APP s.6.11] FC15 and [APP s.6.12] FC16: "The normal response returns the function code,
   --  starting address, and quantity" -- 5 bytes; F1 = starting address, F2 = quantity.
   --  [APP s.6.16] FC22: "The normal response is an echo of the request": function code,
   --  Reference Address, And_Mask, Or_Mask -- 7 bytes; F1 = address, F2 = And_Mask,
   --  F3 = Or_Mask.
   --  The fields are the big-endian words at offsets 2, 4 and 6 [APP s.4.2]. A reply of the
   --  wrong length is Bad_Pdu_Length and its fields are not consulted; a reply whose echoed
   --  field differs from the request's (another address, value, quantity or mask) is
   --  Echo_Mismatch (answered 04, a PLC fault), never relayed as success. F3 is consulted
   --  for FC22 only.

   subtype Echo_Kind is Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind
     range Lovelace_Mb_Fc_Catalog_Pkg.Write_Coil_Fc .. Lovelace_Mb_Fc_Catalog_Pkg.Mask_Write_Fc;

   function Echo_Length (Kind : Echo_Kind) return Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length is
     (if Kind = Lovelace_Mb_Fc_Catalog_Pkg.Mask_Write_Fc then 7 else 5);

   function Fields_Echoed
     (Kind   : Echo_Kind;
      Req_F1 : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Req_F2 : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Req_F3 : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Rep_F1 : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Rep_F2 : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Rep_F3 : Lovelace_Mb_Pdu_Fields_Pkg.Word) return Boolean is
     (Rep_F1 = Req_F1 and then Rep_F2 = Req_F2
      and then (if Kind = Lovelace_Mb_Fc_Catalog_Pkg.Mask_Write_Fc then Rep_F3 = Req_F3));

   function Echo_Verdict
     (Kind   : Echo_Kind;
      N      : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length;
      Req_F1 : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Req_F2 : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Req_F3 : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Rep_F1 : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Rep_F2 : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Rep_F3 : Lovelace_Mb_Pdu_Fields_Pkg.Word) return Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict is
     (if N /= Echo_Length (Kind) then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
      elsif not Fields_Echoed (Kind, Req_F1, Req_F2, Req_F3, Rep_F1, Rep_F2, Rep_F3)
      then Lovelace_Mb_Pdu_Refusal_Pkg.Echo_Mismatch
      else Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
     with Post => (Echo_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
                    = (N = Echo_Length (Kind)
                       and then Rep_F1 = Req_F1 and then Rep_F2 = Req_F2
                       and then (Kind /= Lovelace_Mb_Fc_Catalog_Pkg.Mask_Write_Fc
                                 or else Rep_F3 = Req_F3))
                  and then (if N /= Echo_Length (Kind)
                            then Echo_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length)
                  and then (if N = Echo_Length (Kind) and then Rep_F1 /= Req_F1
                            then Echo_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Echo_Mismatch)
                  and then (if N = Echo_Length (Kind) and then Rep_F2 /= Req_F2
                            then Echo_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Echo_Mismatch)
                  and then (if N = 7 and then Kind = Lovelace_Mb_Fc_Catalog_Pkg.Mask_Write_Fc
                               and then Rep_F3 /= Req_F3
                            then Echo_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Echo_Mismatch)
                  and then Echo_Verdict'Result in Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok
                                            | Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
                                            | Lovelace_Mb_Pdu_Refusal_Pkg.Echo_Mismatch;

end Lovelace_Mb_Resp_Echo_Pkg;
