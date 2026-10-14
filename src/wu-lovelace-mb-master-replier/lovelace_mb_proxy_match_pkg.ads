with Lovelace_Mb_Frame_Refusal_Pkg;
with Lovelace_Mb_Mbap_Pkg;
with Lovelace_Mb_Tcp_Adu_Pkg;

package Lovelace_Mb_Proxy_Match_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Frame_Refusal_Pkg.Frame_Verdict;

   --  The gateway's MBAP decisions [TCP s.3.1.3, s.4.4.1.3].
   --  A reply's header: the Transaction Identifier and the Unit Identifier are
   --  "Recopied by the server from the received request", the Protocol Identifier
   --  is 0 (MODBUS), and the Length is the count of the following bytes: the unit id
   --  plus the PDU, so N + 1 for a PDU of N = 1 .. 253 bytes [APP s.4.1], and the ADU
   --  written is 7 + N bytes (8 .. 260, R-MB-4). Fields are big-endian.
   --  A reply belongs to the request sent only with the same transaction id, the same
   --  unit id, and the request's function code or that code + 16#80# (an exception
   --  reply [APP s.7]); a stale or crossed reply is never relayed (R-MB-18).
   --  An exception PDU is 2 bytes (code + 16#80#, exception code), its ADU 9 bytes.

   type Reply_Mbap is record
      Transaction : Lovelace_Mb_Mbap_Pkg.Word;
      Protocol    : Lovelace_Mb_Mbap_Pkg.Word;
      Length      : Lovelace_Mb_Mbap_Pkg.Word;
      Unit        : Lovelace_Mb_Mbap_Pkg.Octet;
   end record;

   function Pdu_Length_Ok (N : Natural) return Boolean is
     (N >= 1 and then N <= 253);

   function Request_Fc_Ok (Fc : Lovelace_Mb_Mbap_Pkg.Octet) return Boolean is
     (Fc >= 1 and then Fc <= 127);

   function Lo_Byte (W : Lovelace_Mb_Mbap_Pkg.Word) return Lovelace_Mb_Mbap_Pkg.Octet is
     (W mod 256);

   function Hi_Byte (W : Lovelace_Mb_Mbap_Pkg.Word) return Lovelace_Mb_Mbap_Pkg.Octet is
     (W / 256)
     with Post => Lovelace_Mb_Mbap_Pkg.Big_Endian (Hi_Byte'Result, Lo_Byte (W)) = W;

   function Reply_Adu_Length (N : Natural) return Natural is
     (7 + N)
     with Pre  => Pdu_Length_Ok (N),
          Post => Reply_Adu_Length'Result >= 8 and then Reply_Adu_Length'Result <= 260;

   function Reply_Header
     (Tid  : Lovelace_Mb_Mbap_Pkg.Word;
      Unit : Lovelace_Mb_Mbap_Pkg.Octet;
      N    : Natural) return Reply_Mbap is
     ((Transaction => Tid, Protocol => 0, Length => N + 1, Unit => Unit))
     with Pre  => Pdu_Length_Ok (N),
          Post => Reply_Header'Result.Transaction = Tid
                  and then Reply_Header'Result.Unit = Unit
                  and then Lovelace_Mb_Mbap_Pkg.Length_Field_Ok (Reply_Header'Result.Length)
                  and then Lovelace_Mb_Mbap_Pkg.Header_Verdict
                             (Reply_Header'Result.Protocol, Reply_Header'Result.Length)
                           = Lovelace_Mb_Frame_Refusal_Pkg.Frame_Ok
                  and then Lovelace_Mb_Tcp_Adu_Pkg.Adu_Verdict
                             (Reply_Adu_Length (N), Reply_Header'Result.Length)
                           = Lovelace_Mb_Frame_Refusal_Pkg.Frame_Ok
                  and then Lovelace_Mb_Tcp_Adu_Pkg.Pdu_Length_Of (Reply_Header'Result.Length) = N;

   function Reply_Belongs
     (Sent_Tid     : Lovelace_Mb_Mbap_Pkg.Word;
      Sent_Unit    : Lovelace_Mb_Mbap_Pkg.Octet;
      Sent_Fc      : Lovelace_Mb_Mbap_Pkg.Octet;
      Got_Tid      : Lovelace_Mb_Mbap_Pkg.Word;
      Got_Unit     : Lovelace_Mb_Mbap_Pkg.Octet;
      Got_Fc_Byte  : Lovelace_Mb_Mbap_Pkg.Octet) return Boolean is
     (Got_Tid = Sent_Tid
      and then Got_Unit = Sent_Unit
      and then (Got_Fc_Byte = Sent_Fc or else Got_Fc_Byte = Sent_Fc + 16#80#))
     with Pre  => Request_Fc_Ok (Sent_Fc),
          Post => Reply_Belongs'Result
                    = (Got_Tid = Sent_Tid
                       and then Got_Unit = Sent_Unit
                       and then Got_Fc_Byte mod 16#80# = Sent_Fc);

   function Exception_Adu_Length return Natural is
     (9)
     with Post => Exception_Adu_Length'Result = Reply_Adu_Length (2)
                  and then Lovelace_Mb_Tcp_Adu_Pkg.Adu_Verdict (Exception_Adu_Length'Result, 3)
                           = Lovelace_Mb_Frame_Refusal_Pkg.Frame_Ok;

end Lovelace_Mb_Proxy_Match_Pkg;
