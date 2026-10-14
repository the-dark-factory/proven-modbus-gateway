package Lovelace_Mb_Bounds_Pkg with SPARK_Mode, Pure is

   --  R-MB-4 capacities, from the public Modbus specifications (R-MB-1).
   --  [APP s.4.1]: PDU <= 253 bytes = 256 - server address (1) - CRC (2).
   --  [TCP s.3.1.3]: MBAP header 7 bytes; its Length field counts the unit id and the PDU.
   --  [SER s.2.5.1]: RTU ADU = address (1) + PDU + CRC (2) <= 256 bytes.
   --  A length outside its subtype is a named frame refusal by the caller, never a truncation.

   Max_Pdu           : constant := 253;
   Mbap_Header       : constant := 7;
   Unit_Id_Bytes     : constant := 1;
   Min_Length_Field  : constant := 2;
   Max_Length_Field  : constant := 254;
   Min_Tcp_Adu       : constant := 8;
   Max_Tcp_Adu       : constant := 260;
   Rtu_Address_Bytes : constant := 1;
   Rtu_Crc_Bytes     : constant := 2;
   Min_Rtu_Adu       : constant := 4;
   Max_Rtu_Adu       : constant := 256;

   subtype Pdu_Length is Natural range 1 .. Max_Pdu;
   subtype Length_Field_Span is Natural range Min_Length_Field .. Max_Length_Field;
   subtype Tcp_Adu_Length is Natural range Min_Tcp_Adu .. Max_Tcp_Adu;
   subtype Rtu_Adu_Length is Natural range Min_Rtu_Adu .. Max_Rtu_Adu;

   function Pdu_Within (N : Natural) return Boolean is
     (N >= 1 and then N <= Max_Pdu)
     with Post => Pdu_Within'Result = (N in Pdu_Length)
                  and then (if Pdu_Within'Result
                            then N <= Max_Tcp_Adu - Mbap_Header
                                 and then N <= Max_Rtu_Adu - Rtu_Address_Bytes - Rtu_Crc_Bytes);

   function Length_Field_Within (N : Natural) return Boolean is
     (N >= Min_Length_Field and then N <= Max_Length_Field)
     with Post => Length_Field_Within'Result = (N in Length_Field_Span)
                  and then (if Length_Field_Within'Result
                            then N - Unit_Id_Bytes in Pdu_Length
                                 and then N + Mbap_Header - Unit_Id_Bytes in Tcp_Adu_Length);

   function Tcp_Adu_Within (N : Natural) return Boolean is
     (N >= Min_Tcp_Adu and then N <= Max_Tcp_Adu)
     with Post => Tcp_Adu_Within'Result = (N in Tcp_Adu_Length)
                  and then (if Tcp_Adu_Within'Result then N - Mbap_Header in Pdu_Length);

   function Rtu_Adu_Within (N : Natural) return Boolean is
     (N >= Min_Rtu_Adu and then N <= Max_Rtu_Adu)
     with Post => Rtu_Adu_Within'Result = (N in Rtu_Adu_Length)
                  and then (if Rtu_Adu_Within'Result
                            then N - Rtu_Address_Bytes - Rtu_Crc_Bytes in Pdu_Length);

   function Capacities_Consistent return Boolean is
     (Max_Tcp_Adu = Mbap_Header + Max_Pdu
      and then Max_Length_Field = Unit_Id_Bytes + Max_Pdu
      and then Max_Rtu_Adu = Rtu_Address_Bytes + Max_Pdu + Rtu_Crc_Bytes
      and then Min_Length_Field = Unit_Id_Bytes + 1
      and then Min_Tcp_Adu = Mbap_Header + 1
      and then Min_Rtu_Adu = Rtu_Address_Bytes + 1 + Rtu_Crc_Bytes)
     with Post => Capacities_Consistent'Result;

end Lovelace_Mb_Bounds_Pkg;
