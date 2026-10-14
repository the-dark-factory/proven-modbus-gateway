with Lovelace_Mb_Frame_Refusal_Pkg;

package Lovelace_Mb_Mbap_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Frame_Refusal_Pkg.Frame_Verdict;

   --  The MBAP header [TCP s.3.1.3]: 7 bytes B0 .. B6, big-endian fields.
   --  B0 B1 Transaction Identifier, B2 B3 Protocol Identifier (0 = MODBUS),
   --  B4 B5 Length (the count of the following bytes: unit id and PDU), B6 Unit Identifier.
   --  A header whose Protocol Identifier is not 0 is discarded [TCP s.4.4.2.2].
   --  Length bounds 2 .. 254 (R-MB-4): the unit id plus a PDU of 1 .. 253 bytes [APP s.4.1].
   --  Transaction Identifier and Unit Identifier are carried, never judged.

   subtype Octet is Natural range 0 .. 255;
   subtype Word is Natural range 0 .. 65_535;

   function Big_Endian (Hi, Lo : Octet) return Word is
     (Hi * 256 + Lo)
     with Post => Big_Endian'Result / 256 = Hi
                  and then Big_Endian'Result mod 256 = Lo;

   function Transaction_Id (B0, B1 : Octet) return Word is
     (Big_Endian (B0, B1));

   function Protocol_Id (B2, B3 : Octet) return Word is
     (Big_Endian (B2, B3));

   function Length_Field (B4, B5 : Octet) return Word is
     (Big_Endian (B4, B5));

   function Unit_Id (B6 : Octet) return Octet is
     (B6);

   function Protocol_Ok (P : Word) return Boolean is
     (P = 0);

   function Length_Field_Ok (L : Word) return Boolean is
     (L >= 2 and then L <= 254)
     with Post => (if Length_Field_Ok'Result
                   then L - 1 >= 1 and then L - 1 <= 253 and then L + 6 <= 260);

   function Header_Verdict (P, L : Word) return Lovelace_Mb_Frame_Refusal_Pkg.Frame_Verdict is
     (if not Protocol_Ok (P) then Lovelace_Mb_Frame_Refusal_Pkg.Bad_Protocol_Id
      elsif not Length_Field_Ok (L) then Lovelace_Mb_Frame_Refusal_Pkg.Bad_Length_Field
      else Lovelace_Mb_Frame_Refusal_Pkg.Frame_Ok)
     with Post => (Header_Verdict'Result = Lovelace_Mb_Frame_Refusal_Pkg.Frame_Ok)
                    = (P = 0 and then L >= 2 and then L <= 254)
                  and then (if P /= 0
                            then Header_Verdict'Result = Lovelace_Mb_Frame_Refusal_Pkg.Bad_Protocol_Id)
                  and then (if P = 0 and then (L < 2 or else L > 254)
                            then Header_Verdict'Result = Lovelace_Mb_Frame_Refusal_Pkg.Bad_Length_Field);

end Lovelace_Mb_Mbap_Pkg;
