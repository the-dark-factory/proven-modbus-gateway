package Lovelace_Mb_Gate_Refusal_Pkg with SPARK_Mode, Pure is

   --  The named verdicts of the water-gateway policy gate (wave 3) and the exception
   --  code each refusal is answered with (owner ruling R-MB-12), from the exception
   --  codes of [APP s.7]: 01 ILLEGAL FUNCTION, 02 ILLEGAL DATA ADDRESS,
   --  03 ILLEGAL DATA VALUE, 04 SERVER DEVICE FAILURE, 06 SERVER DEVICE BUSY.
   --  Unknown_Master, Function_Not_Allowed -> 01; Address_Not_Writable -> 02;
   --  Mask_On_Limited, Value_Below_Limit, Value_Above_Limit -> 03;
   --  Rate_Exceeded -> 06 (retry later); Forbidden_Sequence -> 04.
   --  Gate_Pass is not a refusal and has no exception code: Gate_Exception takes only
   --  a Gate_Refusal, so a passed request can never be answered with an exception.
   --  The edge logs the verdict NAME, never only the code.

   type Gate_Verdict is
     (Gate_Pass,
      Unknown_Master,
      Function_Not_Allowed,
      Address_Not_Writable,
      Mask_On_Limited,
      Value_Below_Limit,
      Value_Above_Limit,
      Rate_Exceeded,
      Forbidden_Sequence);

   subtype Gate_Refusal is Gate_Verdict range Unknown_Master .. Forbidden_Sequence;

   subtype Exception_Code is Natural range 0 .. 255;

   function Is_Gate_Refusal (V : Gate_Verdict) return Boolean is
     (V /= Gate_Pass)
     with Post => Is_Gate_Refusal'Result = (V in Gate_Refusal);

   function Is_Access_Refusal (V : Gate_Verdict) return Boolean is
     (V = Unknown_Master or else V = Function_Not_Allowed);

   function Is_Value_Refusal (V : Gate_Verdict) return Boolean is
     (V = Mask_On_Limited or else V = Value_Below_Limit or else V = Value_Above_Limit);

   function Gate_Exception (V : Gate_Refusal) return Exception_Code is
     (case V is
         when Unknown_Master | Function_Not_Allowed => 16#01#,
         when Address_Not_Writable => 16#02#,
         when Mask_On_Limited | Value_Below_Limit | Value_Above_Limit => 16#03#,
         when Rate_Exceeded => 16#06#,
         when Forbidden_Sequence => 16#04#)
     with Post => (Gate_Exception'Result = 16#01#) = Is_Access_Refusal (V)
                  and then (Gate_Exception'Result = 16#02#) = (V = Address_Not_Writable)
                  and then (Gate_Exception'Result = 16#03#) = Is_Value_Refusal (V)
                  and then (Gate_Exception'Result = 16#04#) = (V = Forbidden_Sequence)
                  and then (Gate_Exception'Result = 16#06#) = (V = Rate_Exceeded);

end Lovelace_Mb_Gate_Refusal_Pkg;
