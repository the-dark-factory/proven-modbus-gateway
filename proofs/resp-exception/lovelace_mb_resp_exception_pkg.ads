with Lovelace_Mb_Pdu_Refusal_Pkg;
with Lovelace_Mb_Pdu_Fields_Pkg;

package Lovelace_Mb_Resp_Exception_Pkg with SPARK_Mode, Pure is

   --  An exception reply from the PLC, checked against the request that caused it, and the
   --  codes the gateway answers for its own failures to reach the PLC.
   --  [APP s.7]: an exception reply has two fields: the function code with its MSB set,
   --  "exactly 80 hexadecimal higher" than the request's, and one exception code; so its PDU
   --  is N = 2 bytes. The codes V1.1b3 defines are 01, 02, 03, 04, 05, 06, 08, 0A and 0B;
   --  every other code (00, 07, 09, 0C .. FF) is undefined. A reply is checked in field order:
   --  the function byte (Wrong_Exception_Fc), the length (Bad_Exception_Length; the code is
   --  not consulted), the code (Undefined_Exception_Code). Only Exception_Accepted is relayed
   --  as received; every refused exception reply is a malformed reply.
   --  R-MB-14: the gateway's own failures -- PLC unreachable 0A (GATEWAY PATH UNAVAILABLE),
   --  no reply in the timeout 0B (GATEWAY TARGET DEVICE FAILED TO RESPOND), a malformed or
   --  mismatched reply 04 (SERVER DEVICE FAILURE), the code Exception_For gives Echo_Mismatch.

   subtype Request_Code is Natural range 0 .. 16#7F#;

   type Exception_Reply_Verdict is
     (Exception_Accepted,
      Wrong_Exception_Fc,
      Bad_Exception_Length,
      Undefined_Exception_Code);

   type Plc_Failure is (Plc_Unreachable, Plc_Silent, Plc_Malformed);

   function Is_Defined_Code (Code : Lovelace_Mb_Pdu_Fields_Pkg.Octet) return Boolean is
     (Code in 16#01# .. 16#06# | 16#08# | 16#0A# .. 16#0B#)
     with Post => Is_Defined_Code'Result
                    = (Code >= 1 and then Code <= 11 and then Code /= 7 and then Code /= 9);

   function Exception_Reply_Check
     (Request_Fc : Request_Code;
      Fc_Byte    : Lovelace_Mb_Pdu_Fields_Pkg.Octet;
      N          : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length;
      Code       : Lovelace_Mb_Pdu_Fields_Pkg.Octet) return Exception_Reply_Verdict is
     (if Fc_Byte /= Request_Fc + 16#80# then Wrong_Exception_Fc
      elsif N /= 2 then Bad_Exception_Length
      elsif not Is_Defined_Code (Code) then Undefined_Exception_Code
      else Exception_Accepted)
     with Post => (Exception_Reply_Check'Result = Exception_Accepted)
                    = (Fc_Byte = Request_Fc + 128 and then N = 2 and then Is_Defined_Code (Code))
                  and then (if Fc_Byte /= Request_Fc + 128
                            then Exception_Reply_Check'Result = Wrong_Exception_Fc)
                  and then (if Fc_Byte = Request_Fc + 128 and then N /= 2
                            then Exception_Reply_Check'Result = Bad_Exception_Length)
                  and then (if Fc_Byte = Request_Fc + 128 and then N = 2
                               and then not Is_Defined_Code (Code)
                            then Exception_Reply_Check'Result = Undefined_Exception_Code)
                  and then (if Exception_Reply_Check'Result = Exception_Accepted
                            then Fc_Byte >= 16#80# and then Code >= 1 and then Code <= 11
                                 and then Code /= 7 and then Code /= 9);

   function Relayed_Code (Code : Lovelace_Mb_Pdu_Fields_Pkg.Octet)
     return Lovelace_Mb_Pdu_Refusal_Pkg.Exception_Code is
     (Code)
     with Pre => Is_Defined_Code (Code);

   function Relay_Code (F : Plc_Failure) return Lovelace_Mb_Pdu_Refusal_Pkg.Exception_Code is
     (case F is
         when Plc_Unreachable => 16#0A#,
         when Plc_Silent => 16#0B#,
         when Plc_Malformed => 16#04#)
     with Post => (Relay_Code'Result = 10) = (F = Plc_Unreachable)
                  and then (Relay_Code'Result = 11) = (F = Plc_Silent)
                  and then (Relay_Code'Result = 4) = (F = Plc_Malformed)
                  and then (if F = Plc_Malformed
                            then Relay_Code'Result
                                   = Lovelace_Mb_Pdu_Refusal_Pkg.Exception_For
                                       (Lovelace_Mb_Pdu_Refusal_Pkg.Echo_Mismatch))
                  and then Is_Defined_Code (Relay_Code'Result);

end Lovelace_Mb_Resp_Exception_Pkg;
