with Lovelace_Mb_Pdu_Refusal_Pkg;
with Lovelace_Mb_Pdu_Fields_Pkg;
with Lovelace_Mb_Fc_Catalog_Pkg;

package Lovelace_Mb_Resp_Read_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict;
   use type Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind;

   --  The normal reply to a read request, checked against the request that caused it.
   --  [APP s.6.1, s.6.2]: FC1/FC2 reply = function code, Byte Count N*, N* data bytes, where
   --  N* = Quantity / 8, plus 1 when the remainder is not 0 (Bits_Bytes).
   --  [APP s.6.3, s.6.4]: FC3/FC4 reply = function code, Byte Count 2 x N, then N registers.
   --  [APP s.6.17]: FC23 reply = function code, Byte Count 2 x N', N' = Quantity to Read.
   --  So the reply PDU is N = 2 + Byte Count bytes, and the Byte Count is the one the request
   --  implies. A short reply (N < 2) has no byte count: Bad_Pdu_Length, Byte_Count not
   --  consulted. A byte count other than the implied one: Bad_Byte_Count. A byte count that is
   --  not the number of remaining bytes: Bad_Pdu_Length. Data values are not judged.
   --  [APP s.6.21]: the FC43/14 reply is function code, MEI Type, Read Device ID code,
   --  Conformity level, More Follows, Next Object Id, Number of objects (7 bytes), then a list
   --  of objects, each Object Id (1 byte), Object length (1 byte), Object Value (length bytes).
   --  The MEI Type is 14 and the Read Device ID code is the request's ("Same as request").
   --  An object whose Id is at Pos fits when Pos + 1 + Len <= N, tested subtract-first:
   --  Len <= N - Pos - 1, under Pre Pos <= N - 1 (its length byte is present).

   subtype Read_Reply_Kind is Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind
     with Static_Predicate =>
       Read_Reply_Kind in Lovelace_Mb_Fc_Catalog_Pkg.Read_Coils_Fc .. Lovelace_Mb_Fc_Catalog_Pkg.Read_Input_Fc
                        | Lovelace_Mb_Fc_Catalog_Pkg.Read_Write_Fc;

   subtype Next_Position is Positive range 1 .. 254;

   function Implied_Byte_Count
     (Kind     : Read_Reply_Kind;
      Quantity : Lovelace_Mb_Pdu_Fields_Pkg.Item_Quantity) return Natural is
     (if Kind in Lovelace_Mb_Fc_Catalog_Pkg.Read_Bits_Kind
      then Lovelace_Mb_Pdu_Fields_Pkg.Bits_Bytes (Quantity)
      else Lovelace_Mb_Pdu_Fields_Pkg.Word_Bytes (Quantity))
     with Post => (if Kind in Lovelace_Mb_Fc_Catalog_Pkg.Read_Bits_Kind
                   then 8 * Implied_Byte_Count'Result >= Quantity
                        and then 8 * Implied_Byte_Count'Result < Quantity + 8
                   else Implied_Byte_Count'Result = 2 * Quantity);

   function Read_Resp_Verdict
     (Kind       : Read_Reply_Kind;
      Quantity   : Lovelace_Mb_Pdu_Fields_Pkg.Item_Quantity;
      N          : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length;
      Byte_Count : Lovelace_Mb_Pdu_Fields_Pkg.Octet) return Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict is
     (if N < 2 then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
      elsif Byte_Count /= Implied_Byte_Count (Kind, Quantity)
      then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Byte_Count
      elsif not Lovelace_Mb_Pdu_Fields_Pkg.Data_Present (N, 2, Byte_Count)
      then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
      else Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
     with Post => (Read_Resp_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
                    = (N >= 2 and then Byte_Count = Implied_Byte_Count (Kind, Quantity)
                       and then N = 2 + Byte_Count)
                  and then (if N < 2
                            then Read_Resp_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length)
                  and then (if N >= 2 and then Byte_Count /= Implied_Byte_Count (Kind, Quantity)
                            then Read_Resp_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Byte_Count)
                  and then (if N >= 2 and then Byte_Count = Implied_Byte_Count (Kind, Quantity)
                               and then N /= 2 + Byte_Count
                            then Read_Resp_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length)
                  and then (if Read_Resp_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok
                               and then Kind in Lovelace_Mb_Fc_Catalog_Pkg.Read_Bits_Kind
                            then 8 * Byte_Count >= Quantity and then 8 * Byte_Count < Quantity + 8)
                  and then (if Read_Resp_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok
                               and then Kind not in Lovelace_Mb_Fc_Catalog_Pkg.Read_Bits_Kind
                            then Byte_Count = 2 * Quantity and then Quantity <= 125);

   function Device_Id_Head_Verdict
     (N            : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length;
      Mei          : Lovelace_Mb_Pdu_Fields_Pkg.Octet;
      Read_Code    : Lovelace_Mb_Pdu_Fields_Pkg.Octet;
      Request_Code : Lovelace_Mb_Pdu_Fields_Pkg.Octet) return Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict is
     (if N < 7 then Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length
      elsif Mei /= 16#0E# or else Read_Code /= Request_Code
      then Lovelace_Mb_Pdu_Refusal_Pkg.Echo_Mismatch
      else Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
     with Post => (Device_Id_Head_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Ok)
                    = (N >= 7 and then Mei = 14 and then Read_Code = Request_Code)
                  and then (if N < 7
                            then Device_Id_Head_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Bad_Pdu_Length)
                  and then (if N >= 7 and then (Mei /= 14 or else Read_Code /= Request_Code)
                            then Device_Id_Head_Verdict'Result = Lovelace_Mb_Pdu_Refusal_Pkg.Echo_Mismatch);

   function Object_Fits
     (N   : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length;
      Pos : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Index;
      Len : Lovelace_Mb_Pdu_Fields_Pkg.Octet) return Boolean is
     (Len <= N - Pos - 1)
     with Pre => Pos <= N - 1,
          Post => Object_Fits'Result = (Pos + 1 + Len <= N)
                  and then (if Object_Fits'Result and then Len >= 1
                            then Lovelace_Mb_Pdu_Fields_Pkg.Field_Present (N, Pos + 2, Len));

   function Next_Object_Pos
     (N   : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length;
      Pos : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Index;
      Len : Lovelace_Mb_Pdu_Fields_Pkg.Octet) return Next_Position is
     (Pos + 2 + Len)
     with Pre => Pos <= N - 1 and then Object_Fits (N, Pos, Len),
          Post => Next_Object_Pos'Result = Pos + 2 + Len
                  and then Next_Object_Pos'Result > Pos + 1
                  and then Next_Object_Pos'Result <= N + 1;

end Lovelace_Mb_Resp_Read_Pkg;
