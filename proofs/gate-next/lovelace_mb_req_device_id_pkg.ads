with Lovelace_Mb_Pdu_Refusal_Pkg;
with Lovelace_Mb_Pdu_Fields_Pkg;

package Lovelace_Mb_Req_Device_Id_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict;

   --  FC43 Encapsulated Interface Transport [APP s.6.19]: function code, MEI type (1 byte),
   --  then MEI type specific data. Only MEI type 14 (16#0E#), Read Device Identification
   --  [APP s.6.21], is in scope; every other MEI type, 13 (CANopen [APP s.6.20]) included,
   --  is Unsupported_Mei_Type, answered 01 like an unsupported function (R-MB-10).
   --  A 43/14 request is function code, MEI type, Read Device ID code (1 byte, 01 to 04) and
   --  Object Id (1 byte), so N = 4 bytes. Tested in this order: a PDU with no MEI type byte
   --  (03, "the implied length is incorrect" [APP s.7]); the MEI type (01); a 43/14 PDU of a
   --  length other than 4 (03); the Read Device ID code, 01 to 04 (03: Figure 30, "Read
   --  deviceId Code OK" no -> 03); else Pdu_Ok. Every Object Id 0 .. 255 is legal here: an
   --  unknown object is the server's to answer (02 for individual access, else a restart at
   --  object 0 [APP s.6.21]), so the Object Id is not a parameter. The Read Device ID code is
   --  consulted only when N = 4; the MEI type only when N >= 2.

   function Device_Id_Verdict
     (N        : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length;
      Mei      : Lovelace_Mb_Pdu_Fields_Pkg.Octet;
      Dev_Code : Lovelace_Mb_Pdu_Fields_Pkg.Octet) return Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict is
     (if N < 2 then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
      elsif Mei = 16#0E#
      then (if N /= 4 then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
            elsif Dev_Code < 1 or else Dev_Code > 4 then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Device_Id_Code
            else Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
      else Lovelace_Mb_Pdu_Refusal_Pkg.Unsupported_Mei_Type)
     with Post => (Device_Id_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
                    = (N = 4 and then Mei = 14 and then Dev_Code >= 1 and then Dev_Code <= 4)
                  and then (if N < 2
                            then Device_Id_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length)
                  and then (if N >= 2 and then Mei /= 14
                            then Device_Id_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Unsupported_Mei_Type)
                  and then (if Mei = 14 and then N /= 4
                            then Device_Id_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length)
                  and then (if N = 4 and then Mei = 14 and then (Dev_Code < 1 or else Dev_Code > 4)
                            then Device_Id_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Device_Id_Code)
                  and then Device_Id_Verdict'Result /= Lovelace_Mb_Pdu_Refusal_Pkg.Address_Overflow;

end Lovelace_Mb_Req_Device_Id_Pkg;
