with Lovelace_Mb_Policy_Shape_Pkg;

package Lovelace_Mb_Rate_Window_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms;

   --  The write-rate rule of the water-gateway policy (wave 3): per master slot at most
   --  Max_Writes passed writes in one window of Window_Ms milliseconds (e.g. 5 writes per
   --  10_000 ms, R-MB-19). A window opens at the first passed write after the previous
   --  window expired and lasts Window_Ms; a window has expired when Now - Window_Start
   --  >= Window_Ms (subtract-first, Now >= Window_Start). A refusal is Rate_Exceeded,
   --  exception 06 (R-MB-12). Time is a parameter, never read here (R-MB-17); only a
   --  passed write calls Next_Rate (gate-next).

   subtype Write_Count is Natural range 0 .. 1_000;

   type Rate_State is record
      Window_Start : Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms;
      Count        : Write_Count;
   end record;

   type Rate_States is array (Lovelace_Mb_Policy_Shape_Pkg.Known_Slot) of Rate_State;

   function Initial_Rate return Rate_State is
     ((Window_Start => 0, Count => 0));

   function Window_Expired
     (S   : Rate_State;
      Now : Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms;
      R   : Lovelace_Mb_Policy_Shape_Pkg.Rate_Rule) return Boolean is
     (Now - S.Window_Start >= Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms (R.Window_Ms))
     with Pre => Now >= S.Window_Start,
          Post => Window_Expired'Result
                    = (S.Window_Start + Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms (R.Window_Ms) <= Now);

   function Rate_Ok
     (S   : Rate_State;
      Now : Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms;
      R   : Lovelace_Mb_Policy_Shape_Pkg.Rate_Rule) return Boolean is
     (Window_Expired (S, Now, R) or else S.Count < R.Max_Writes)
     with Pre => Now >= S.Window_Start,
          Post => (if S.Count < R.Max_Writes then Rate_Ok'Result)
                  and then (if Now - S.Window_Start >= Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms (R.Window_Ms)
                            then Rate_Ok'Result)
                  and then (if S.Count >= R.Max_Writes
                               and then Now - S.Window_Start < Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms (R.Window_Ms)
                            then not Rate_Ok'Result);

   function Next_Rate
     (S   : Rate_State;
      Now : Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms;
      R   : Lovelace_Mb_Policy_Shape_Pkg.Rate_Rule) return Rate_State is
     (if Window_Expired (S, Now, R)
      then (Window_Start => Now, Count => 1)
      else (Window_Start => S.Window_Start, Count => S.Count + 1))
     with Pre => Now >= S.Window_Start
                 and then Lovelace_Mb_Policy_Shape_Pkg.Rate_Rule_Ok (R)
                 and then Rate_Ok (S, Now, R),
          Post => Next_Rate'Result.Count >= 1
                  and then Next_Rate'Result.Count <= R.Max_Writes
                  and then Next_Rate'Result.Window_Start >= S.Window_Start
                  and then Next_Rate'Result.Window_Start <= Now
                  and then (if Now - S.Window_Start < Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms (R.Window_Ms)
                            then Next_Rate'Result.Window_Start = S.Window_Start
                                 and then Next_Rate'Result.Count = S.Count + 1)
                  and then (if Now - S.Window_Start >= Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms (R.Window_Ms)
                            then Next_Rate'Result.Window_Start = Now
                                 and then Next_Rate'Result.Count = 1);

end Lovelace_Mb_Rate_Window_Pkg;
