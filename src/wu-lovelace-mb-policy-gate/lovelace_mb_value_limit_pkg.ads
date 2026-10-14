with Lovelace_Mb_Policy_Shape_Pkg;

package Lovelace_Mb_Value_Limit_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Policy_Shape_Pkg.Write_Target;

   --  The value limits of the water-gateway policy (wave 3): a holding register may carry
   --  one declared limit [Min, Max] (e.g. the chlorine dosing setpoint, R-MB-19). A register
   --  write (FC6, FC16, the write part of FC23 [APP s.6.6, s.6.12, s.6.17]) passes only if
   --  EVERY value it writes lies inside the limit of its register; a register with no limit
   --  takes any value. Coil writes carry no limits. A refusal is Value_Below_Limit or
   --  Value_Above_Limit, exception 03 (R-MB-12, R-MB-21); Below_Any tells them apart.
   --  Has_Limit serves Mask_On_Limited (R-MB-13). Values V (K) is the value written to
   --  Start + K - 1, K = 1 .. Qty; Qty <= 65536 - Start (the span rule, subtract-first).

   function Has_Limit
     (T : Lovelace_Mb_Policy_Shape_Pkg.Policy_Table;
      A : Lovelace_Mb_Policy_Shape_Pkg.Item_Address) return Boolean is
     (for some I in 1 .. T.Limit_Count => T.Limits (I).Register = A);

   function Value_Ok
     (T : Lovelace_Mb_Policy_Shape_Pkg.Policy_Table;
      A : Lovelace_Mb_Policy_Shape_Pkg.Item_Address;
      V : Lovelace_Mb_Policy_Shape_Pkg.Item_Value) return Boolean is
     (for all I in 1 .. T.Limit_Count =>
        (if T.Limits (I).Register = A then V >= T.Limits (I).Min and then V <= T.Limits (I).Max))
     with Post => (if not Has_Limit (T, A) then Value_Ok'Result)
                  and then (if (for some I in 1 .. T.Limit_Count =>
                                  T.Limits (I).Register = A
                                  and then (V < T.Limits (I).Min or else V > T.Limits (I).Max))
                            then not Value_Ok'Result);

   function Values_Ok
     (T      : Lovelace_Mb_Policy_Shape_Pkg.Policy_Table;
      Target : Lovelace_Mb_Policy_Shape_Pkg.Write_Target;
      Start  : Lovelace_Mb_Policy_Shape_Pkg.Item_Address;
      Qty    : Lovelace_Mb_Policy_Shape_Pkg.Write_Quantity;
      Values : Lovelace_Mb_Policy_Shape_Pkg.Written_Values) return Boolean is
     (Target = Lovelace_Mb_Policy_Shape_Pkg.Coil_Target
      or else (for all K in 1 .. Qty => Value_Ok (T, Start + K - 1, Values (K))))
     with Pre => Qty <= 65_536 - Start,
          Post => (if Target = Lovelace_Mb_Policy_Shape_Pkg.Register_Target
                      and then (for some K in 1 .. Qty =>
                                  (for some I in 1 .. T.Limit_Count =>
                                     T.Limits (I).Register = Start + K - 1
                                     and then (Values (K) < T.Limits (I).Min
                                               or else Values (K) > T.Limits (I).Max)))
                   then not Values_Ok'Result)
                  and then (if (for all K in 1 .. Qty =>
                                  (for all I in 1 .. T.Limit_Count =>
                                     T.Limits (I).Register /= Start + K - 1))
                            then Values_Ok'Result)
                  and then (if Target = Lovelace_Mb_Policy_Shape_Pkg.Coil_Target then Values_Ok'Result);

   function Below_Any
     (T      : Lovelace_Mb_Policy_Shape_Pkg.Policy_Table;
      Target : Lovelace_Mb_Policy_Shape_Pkg.Write_Target;
      Start  : Lovelace_Mb_Policy_Shape_Pkg.Item_Address;
      Qty    : Lovelace_Mb_Policy_Shape_Pkg.Write_Quantity;
      Values : Lovelace_Mb_Policy_Shape_Pkg.Written_Values) return Boolean is
     (Target = Lovelace_Mb_Policy_Shape_Pkg.Register_Target
      and then (for some K in 1 .. Qty =>
                  (for some I in 1 .. T.Limit_Count =>
                     T.Limits (I).Register = Start + K - 1 and then Values (K) < T.Limits (I).Min)))
     with Pre => Qty <= 65_536 - Start,
          Post => (if Below_Any'Result then not Values_Ok (T, Target, Start, Qty, Values))
                  and then (if not Values_Ok (T, Target, Start, Qty, Values) and then not Below_Any'Result
                            then (for some K in 1 .. Qty =>
                                    (for some I in 1 .. T.Limit_Count =>
                                       T.Limits (I).Register = Start + K - 1
                                       and then Values (K) > T.Limits (I).Max)));

end Lovelace_Mb_Value_Limit_Pkg;
