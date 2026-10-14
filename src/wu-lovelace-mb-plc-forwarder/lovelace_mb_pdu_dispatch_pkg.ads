with Lovelace_Mb_Pdu_Refusal_Pkg;
with Lovelace_Mb_Pdu_Fields_Pkg;
with Lovelace_Mb_Fc_Catalog_Pkg;
with Lovelace_Mb_Req_Read_Bits_Pkg;
with Lovelace_Mb_Req_Read_Words_Pkg;
with Lovelace_Mb_Req_Write_Single_Pkg;
with Lovelace_Mb_Req_Write_Coils_Pkg;
with Lovelace_Mb_Req_Write_Registers_Pkg;
with Lovelace_Mb_Req_Mask_Write_Pkg;
with Lovelace_Mb_Req_Read_Write_Pkg;
with Lovelace_Mb_Req_Device_Id_Pkg;

package Lovelace_Mb_Pdu_Dispatch_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict;
   use type Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind;

   --  One received request PDU, P (1 .. N) [APP s.4.1], judged by the request core of its own
   --  function code. The function code is P (1), always present (N >= 1). For every code in
   --  scope the fixed head (function code and fixed-width fields) is checked present BEFORE
   --  any field is read (Short_Head); every field is read through Byte_At / Word_At under
   --  Field_Present. An unsupported code is Unknown_Function, 01 (R-MB-10).
   --  Head widths: FC1-6 5 bytes; FC15/16 6 (to the byte count); FC22 7; FC23 10 (to the write
   --  byte count); FC43 2 (to the MEI type, so an MEI type other than 14 is 01 whatever the
   --  length). Request_Verdict's Post states, code by code, that it equals that code's own
   --  verdict. A Pdu_Ok request is read through the request-view core (Request_Ok is its Pre).
   --  Exception responses [APP s.7]: the function code with its most significant bit set,
   --  then the exception code of the refusal (R-MB-8, R-MB-10).

   function Kind_Of (P : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes) return Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind is
     (Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind_Of (P (1)));

   function Head_Width
     (K : Lovelace_Mb_Fc_Catalog_Pkg.Public_Kind) return Lovelace_Mb_Pdu_Fields_Pkg.Field_Width is
     (case K is
         when Lovelace_Mb_Fc_Catalog_Pkg.Read_Bits_Kind | Lovelace_Mb_Fc_Catalog_Pkg.Read_Words_Kind
            | Lovelace_Mb_Fc_Catalog_Pkg.Single_Write_Kind => 5,
         when Lovelace_Mb_Fc_Catalog_Pkg.Write_Coils_Fc | Lovelace_Mb_Fc_Catalog_Pkg.Write_Registers_Fc => 6,
         when Lovelace_Mb_Fc_Catalog_Pkg.Mask_Write_Fc => 7,
         when Lovelace_Mb_Fc_Catalog_Pkg.Read_Write_Fc => 10,
         when Lovelace_Mb_Fc_Catalog_Pkg.Encapsulated_Fc => 2)
     with Post => Head_Width'Result >= 2 and then Head_Width'Result <= 10
                  and then (if K /= Lovelace_Mb_Fc_Catalog_Pkg.Encapsulated_Fc then Head_Width'Result >= 5);

   function Short_Head
     (K : Lovelace_Mb_Fc_Catalog_Pkg.Public_Kind; N : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length) return Boolean is
     (N < Head_Width (K));

   function Request_Verdict
     (P : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes;
      N : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length) return Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict is
     (case Kind_Of (P) is
         when Lovelace_Mb_Fc_Catalog_Pkg.Unsupported_Fc => Lovelace_Mb_Pdu_Refusal_Pkg.Unknown_Function,
         when Lovelace_Mb_Fc_Catalog_Pkg.Read_Bits_Kind =>
           (if Short_Head (Kind_Of (P), N) then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
            else Lovelace_Mb_Req_Read_Bits_Pkg.Read_Bits_Verdict
                   (N, Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 2), Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 4))),
         when Lovelace_Mb_Fc_Catalog_Pkg.Read_Words_Kind =>
           (if Short_Head (Kind_Of (P), N) then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
            else Lovelace_Mb_Req_Read_Words_Pkg.Read_Words_Verdict
                   (N, Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 2), Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 4))),
         when Lovelace_Mb_Fc_Catalog_Pkg.Single_Write_Kind =>
           (if Short_Head (Kind_Of (P), N) then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
            else Lovelace_Mb_Req_Write_Single_Pkg.Write_Single_Verdict
                   (Kind_Of (P), N, Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 4))),
         when Lovelace_Mb_Fc_Catalog_Pkg.Write_Coils_Fc =>
           (if Short_Head (Kind_Of (P), N) then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
            else Lovelace_Mb_Req_Write_Coils_Pkg.Write_Coils_Verdict
                   (N, Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 2), Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 4),
                    Lovelace_Mb_Pdu_Fields_Pkg.Byte_At (P, N, 6))),
         when Lovelace_Mb_Fc_Catalog_Pkg.Write_Registers_Fc =>
           (if Short_Head (Kind_Of (P), N) then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
            else Lovelace_Mb_Req_Write_Registers_Pkg.Write_Registers_Verdict
                   (N, Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 2), Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 4),
                    Lovelace_Mb_Pdu_Fields_Pkg.Byte_At (P, N, 6))),
         when Lovelace_Mb_Fc_Catalog_Pkg.Mask_Write_Fc =>
           (if Short_Head (Kind_Of (P), N) then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
            else Lovelace_Mb_Req_Mask_Write_Pkg.Mask_Write_Verdict (N)),
         when Lovelace_Mb_Fc_Catalog_Pkg.Read_Write_Fc =>
           (if Short_Head (Kind_Of (P), N) then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
            else Lovelace_Mb_Req_Read_Write_Pkg.Read_Write_Verdict
                   (N, Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 2), Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 4),
                    Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 6), Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 8),
                    Lovelace_Mb_Pdu_Fields_Pkg.Byte_At (P, N, 10))),
         when Lovelace_Mb_Fc_Catalog_Pkg.Encapsulated_Fc =>
           (if Short_Head (Kind_Of (P), N) then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
            else Lovelace_Mb_Req_Device_Id_Pkg.Device_Id_Verdict
                   (N, Lovelace_Mb_Pdu_Fields_Pkg.Byte_At (P, N, 2),
                    (if Lovelace_Mb_Pdu_Fields_Pkg.Field_Present (N, 3, 1)
                     then Lovelace_Mb_Pdu_Fields_Pkg.Byte_At (P, N, 3) else 0))))
     with Post => (Request_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Unknown_Function)
                    = (Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Unsupported_Fc)
                  and then Request_Verdict'Result /= Lovelace_Mb_Pdu_Refusal_Pkg.Echo_Mismatch
                  and then (if Kind_Of (P) /= Lovelace_Mb_Fc_Catalog_Pkg.Unsupported_Fc
                               and then Short_Head (Kind_Of (P), N)
                            then Request_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length)
                  and then (if Request_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok
                            then Kind_Of (P) /= Lovelace_Mb_Fc_Catalog_Pkg.Unsupported_Fc
                                 and then not Short_Head (Kind_Of (P), N))
                  and then (if Kind_Of (P) in Lovelace_Mb_Fc_Catalog_Pkg.Read_Bits_Kind and then N >= 5
                            then Request_Verdict'Result
                                 = Lovelace_Mb_Req_Read_Bits_Pkg.Read_Bits_Verdict
                                     (N, Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 2),
                                      Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 4)))
                  and then (if Kind_Of (P) in Lovelace_Mb_Fc_Catalog_Pkg.Read_Words_Kind and then N >= 5
                            then Request_Verdict'Result
                                 = Lovelace_Mb_Req_Read_Words_Pkg.Read_Words_Verdict
                                     (N, Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 2),
                                      Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 4)))
                  and then (if Kind_Of (P) in Lovelace_Mb_Fc_Catalog_Pkg.Single_Write_Kind and then N >= 5
                            then Request_Verdict'Result
                                 = Lovelace_Mb_Req_Write_Single_Pkg.Write_Single_Verdict
                                     (Kind_Of (P), N, Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 4)))
                  and then (if Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Write_Coils_Fc and then N >= 6
                            then Request_Verdict'Result
                                 = Lovelace_Mb_Req_Write_Coils_Pkg.Write_Coils_Verdict
                                     (N, Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 2),
                                      Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 4),
                                      Lovelace_Mb_Pdu_Fields_Pkg.Byte_At (P, N, 6)))
                  and then (if Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Write_Registers_Fc and then N >= 6
                            then Request_Verdict'Result
                                 = Lovelace_Mb_Req_Write_Registers_Pkg.Write_Registers_Verdict
                                     (N, Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 2),
                                      Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 4),
                                      Lovelace_Mb_Pdu_Fields_Pkg.Byte_At (P, N, 6)))
                  and then (if Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Mask_Write_Fc
                            then Request_Verdict'Result = Lovelace_Mb_Req_Mask_Write_Pkg.Mask_Write_Verdict (N))
                  and then (if Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Read_Write_Fc and then N >= 10
                            then Request_Verdict'Result
                                 = Lovelace_Mb_Req_Read_Write_Pkg.Read_Write_Verdict
                                     (N, Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 2),
                                      Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 4),
                                      Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 6),
                                      Lovelace_Mb_Pdu_Fields_Pkg.Word_At (P, N, 8),
                                      Lovelace_Mb_Pdu_Fields_Pkg.Byte_At (P, N, 10)))
                  and then (if Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Encapsulated_Fc and then N >= 4
                            then Request_Verdict'Result
                                 = Lovelace_Mb_Req_Device_Id_Pkg.Device_Id_Verdict
                                     (N, Lovelace_Mb_Pdu_Fields_Pkg.Byte_At (P, N, 2),
                                      Lovelace_Mb_Pdu_Fields_Pkg.Byte_At (P, N, 3)));

   function Request_Ok
     (P : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes; N : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length) return Boolean is
     (Request_Verdict (P, N) = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok);

   type Exception_Reply is record
      Fc_Byte : Lovelace_Mb_Pdu_Fields_Pkg.Octet;
      Code    : Lovelace_Mb_Pdu_Refusal_Pkg.Exception_Code;
   end record;

   --  [APP s.7]: the exception function code is the request's with its most significant bit
   --  set to 1. A request byte that already has it set (reserved [APP s.4.1]) keeps it.
   function Exception_Fc_Byte (Fc : Lovelace_Mb_Pdu_Fields_Pkg.Octet) return Lovelace_Mb_Pdu_Fields_Pkg.Octet is
     (if Fc < 16#80# then Fc + 16#80# else Fc)
     with Post => Exception_Fc_Byte'Result >= 16#80#
                  and then Exception_Fc_Byte'Result mod 16#80# = Fc mod 16#80#
                  and then (if Fc < 16#80# then Exception_Fc_Byte'Result = Fc + 16#80#);

   function Exception_Pdu
     (Fc : Lovelace_Mb_Pdu_Fields_Pkg.Octet;
      R  : Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Refusal) return Exception_Reply is
     ((Fc_Byte => Exception_Fc_Byte (Fc), Code => Lovelace_Mb_Pdu_Refusal_Pkg.Exception_For (R)))
     with Post => Exception_Pdu'Result.Fc_Byte >= 16#80#
                  and then (if Fc >= 1 and then Fc < 16#80# then Exception_Pdu'Result.Fc_Byte >= 16#81#)
                  and then Exception_Pdu'Result.Code = Lovelace_Mb_Pdu_Refusal_Pkg.Exception_For (R)
                  and then (if Lovelace_Mb_Pdu_Refusal_Pkg.Unknown_Function = R
                            then Exception_Pdu'Result.Code = 1);

   --  The exception response to a refused request.
   function Refusal_Reply
     (P : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes;
      N : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length) return Exception_Reply is
     (Exception_Pdu (P (1), Request_Verdict (P, N)))
     with Pre => not Request_Ok (P, N),
          Post => Refusal_Reply'Result.Code /= 4
                  and then (if Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Unsupported_Fc
                            then Refusal_Reply'Result.Code = 1);

end Lovelace_Mb_Pdu_Dispatch_Pkg;
