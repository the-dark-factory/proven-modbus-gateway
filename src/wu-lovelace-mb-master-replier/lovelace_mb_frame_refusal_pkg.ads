package Lovelace_Mb_Frame_Refusal_Pkg with SPARK_Mode, Pure is

   --  The named frame verdicts of the Modbus framers (TCP MBAP and RTU), R-MB-9.
   --  A malformed ADU is discarded with no response:
   --  [TCP s.4.4.2.2] a bad MBAP header: "the indication is simply discarded";
   --  [SER s.2.5.1.1, s.2.5.1.2] an incomplete frame or a CRC error: the frame is discarded.
   --  A bad TCP Length field leaves the byte stream with no frame boundary, so the
   --  connection is closed (R-MB-9); every other refusal keeps the connection.

   type Frame_Verdict is
     (Frame_Ok,
      Bad_Protocol_Id,
      Bad_Length_Field,
      Short_Adu,
      Long_Adu,
      Bad_Crc,
      Reserved_Address);

   type Frame_Answer_Kind is (Answer_Pass, Answer_Silent);

   function Is_Refusal (V : Frame_Verdict) return Boolean is
     (V /= Frame_Ok);

   function Frame_Answer (V : Frame_Verdict) return Frame_Answer_Kind is
     (case V is
         when Frame_Ok => Answer_Pass,
         when Bad_Protocol_Id | Bad_Length_Field | Short_Adu | Long_Adu
            | Bad_Crc | Reserved_Address => Answer_Silent)
     with Post => (if Is_Refusal (V) then Frame_Answer'Result = Answer_Silent)
                  and then (if V = Frame_Ok then Frame_Answer'Result = Answer_Pass);

   function Closes_Tcp_Connection (V : Frame_Verdict) return Boolean is
     (V = Bad_Length_Field)
     with Post => (if Closes_Tcp_Connection'Result
                   then Is_Refusal (V) and then Frame_Answer (V) = Answer_Silent);

end Lovelace_Mb_Frame_Refusal_Pkg;
