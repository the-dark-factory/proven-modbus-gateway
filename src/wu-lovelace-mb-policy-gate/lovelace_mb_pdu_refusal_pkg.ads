package Lovelace_Mb_Pdu_Refusal_Pkg with SPARK_Mode, Pure is

   --  The named PDU verdicts of the Modbus request parser, and the exception code each
   --  refusal is answered with (R-MB-8), from the public Modbus specification.
   --  [APP s.6.1 - s.6.21] state diagrams: function code not supported -> 01; a quantity or
   --  value outside its range -> 03; starting address + quantity out of range -> 02.
   --  [APP s.7]: 03 also covers "the implied length is incorrect"; 04 is a server failure.
   --  [APP s.6.19 - s.6.21], R-MB-10: an MEI type other than 14 is not supported -> 01.
   --  Echo_Mismatch is a fault in a REPLY from the PLC, never in a request: 04.
   --  No request refusal is answered with 04.

   type Pdu_Verdict is
     (Pdu_Ok,
      Unknown_Function,
      Unsupported_Mei_Type,
      Bad_Pdu_Length,
      Bad_Quantity,
      Bad_Byte_Count,
      Bad_Coil_Value,
      Bad_Device_Id_Code,
      Address_Overflow,
      Echo_Mismatch);

   subtype Pdu_Refusal is Pdu_Verdict range Unknown_Function .. Echo_Mismatch;

   subtype Exception_Code is Natural range 1 .. 11;

   function Is_Pdu_Refusal (V : Pdu_Verdict) return Boolean is
     (V /= Pdu_Ok);

   function Is_Request_Refusal (V : Pdu_Verdict) return Boolean is
     (V /= Pdu_Ok and then V /= Echo_Mismatch);

   function Exception_For (R : Pdu_Refusal) return Exception_Code is
     (case R is
         when Unknown_Function | Unsupported_Mei_Type => 1,
         when Address_Overflow => 2,
         when Bad_Pdu_Length | Bad_Quantity | Bad_Byte_Count | Bad_Coil_Value
            | Bad_Device_Id_Code => 3,
         when Echo_Mismatch => 4)
     with Post => (Exception_For'Result = 1)
                    = (R in Unknown_Function | Unsupported_Mei_Type)
                  and then (Exception_For'Result = 2) = (R = Address_Overflow)
                  and then (Exception_For'Result = 3)
                    = (R = Bad_Pdu_Length or else R = Bad_Quantity or else R = Bad_Byte_Count
                       or else R = Bad_Coil_Value or else R = Bad_Device_Id_Code)
                  and then (Exception_For'Result = 4) = (R = Echo_Mismatch)
                  and then (if Is_Request_Refusal (R) then Exception_For'Result /= 4);

end Lovelace_Mb_Pdu_Refusal_Pkg;
