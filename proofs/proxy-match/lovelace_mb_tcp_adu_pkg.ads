with Lovelace_Mb_Frame_Refusal_Pkg;
with Lovelace_Mb_Mbap_Pkg;

package Lovelace_Mb_Tcp_Adu_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Frame_Refusal_Pkg.Frame_Verdict;

   --  The TCP ADU length [TCP s.3.1.3]: the 7-byte MBAP header, whose Length field L counts
   --  the bytes that follow its first 6 (the unit id and the PDU), so a whole ADU is 6 + L
   --  bytes and its PDU is L - 1 bytes. Under Length_Field_Ok (2 <= L <= 254, R-MB-4) the
   --  PDU is 1 .. 253 bytes [APP s.4.1] and the ADU 8 .. 260 bytes.
   --  Subtract-first: Received - 6 is formed only after Received >= 7 is known.

   function Bytes_To_Read (L : Lovelace_Mb_Mbap_Pkg.Word) return Natural is
     (L - 1)
     with Pre  => Lovelace_Mb_Mbap_Pkg.Length_Field_Ok (L),
          Post => Bytes_To_Read'Result >= 1 and then Bytes_To_Read'Result <= 253;

   function Pdu_Length_Of (L : Lovelace_Mb_Mbap_Pkg.Word) return Natural is
     (L - 1)
     with Pre  => Lovelace_Mb_Mbap_Pkg.Length_Field_Ok (L),
          Post => Pdu_Length_Of'Result >= 1 and then Pdu_Length_Of'Result <= 253;

   function Adu_Verdict
     (Received : Natural; L : Lovelace_Mb_Mbap_Pkg.Word)
      return Lovelace_Mb_Frame_Refusal_Pkg.Frame_Verdict is
     (if Received < 7 then Lovelace_Mb_Frame_Refusal_Pkg.Short_Adu
      elsif Received - 6 < L then Lovelace_Mb_Frame_Refusal_Pkg.Short_Adu
      elsif Received - 6 > L then Lovelace_Mb_Frame_Refusal_Pkg.Long_Adu
      else Lovelace_Mb_Frame_Refusal_Pkg.Frame_Ok)
     with Pre  => Lovelace_Mb_Mbap_Pkg.Length_Field_Ok (L),
          Post => (Adu_Verdict'Result = Lovelace_Mb_Frame_Refusal_Pkg.Frame_Ok)
                    = (Received >= 7 and then Received - 6 = L)
                  and then (if Adu_Verdict'Result = Lovelace_Mb_Frame_Refusal_Pkg.Frame_Ok
                            then Received >= 8 and then Received <= 260
                                 and then Received - 7 = Pdu_Length_Of (L))
                  and then (if Received < 7
                            then Adu_Verdict'Result = Lovelace_Mb_Frame_Refusal_Pkg.Short_Adu)
                  and then (if Received >= 7 and then Received - 6 > L
                            then Adu_Verdict'Result = Lovelace_Mb_Frame_Refusal_Pkg.Long_Adu);

end Lovelace_Mb_Tcp_Adu_Pkg;
