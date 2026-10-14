with Lovelace_Mb_Pdu_Refusal_Pkg;
with Lovelace_Mb_Pdu_Fields_Pkg;
with Lovelace_Mb_Addr_Span_Pkg;

package Lovelace_Mb_Req_Read_Bits_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict;

   --  FC1 Read Coils and FC2 Read Discrete Inputs requests [APP s.6.1, s.6.2]:
   --  function code, Starting Address (2 bytes, 16#0000# to 16#FFFF#), Quantity (2 bytes,
   --  1 to 2000, 16#07D0#), so N = 5 bytes. Tested in the order of the state diagrams
   --  (Figures 11 and 12): the PDU length (03, "the implied length is incorrect" [APP s.7]),
   --  then the quantity (03), then Starting Address + Quantity (02, R-MB-8); else Pdu_Ok.
   --  The quantity is tested BEFORE the address, so a bad quantity is 03 whatever the address.
   --  Start and Quantity are the two big-endian words at offsets 2 and 4; when N /= 5 they are
   --  not consulted.

   function Read_Bits_Verdict
     (N        : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length;
      Start    : Lovelace_Mb_Pdu_Fields_Pkg.Word;
      Quantity : Lovelace_Mb_Pdu_Fields_Pkg.Word) return Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict is
     (if N /= 5 then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
      elsif Quantity < 1 or else Quantity > 16#07D0# then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Quantity
      elsif not Lovelace_Mb_Addr_Span_Pkg.Span_Ok (Start, Quantity)
      then Lovelace_Mb_Pdu_Refusal_Pkg.Address_Overflow
      else Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
     with Post => (Read_Bits_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
                    = (N = 5 and then Quantity >= 1 and then Quantity <= 2_000
                       and then Start + Quantity <= 65_536)
                  and then (if N /= 5
                            then Read_Bits_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length)
                  and then (if N = 5 and then (Quantity < 1 or else Quantity > 2_000)
                            then Read_Bits_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Quantity)
                  and then (if N = 5 and then Quantity >= 1 and then Quantity <= 2_000
                               and then Start + Quantity > 65_536
                            then Read_Bits_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Address_Overflow);

end Lovelace_Mb_Req_Read_Bits_Pkg;
