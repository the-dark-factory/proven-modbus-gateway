with Lovelace_Mb_Policy_Shape_Pkg;

package Lovelace_Mb_Write_Range_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Policy_Shape_Pkg.Write_Target;

   --  The declared writable map of the water-gateway policy (wave 3). A write of Qty items
   --  of one Target (coils for FC5/FC15, holding registers for FC6/FC16/FC22/FC23
   --  [APP s.6.5, s.6.6, s.6.11, s.6.12, s.6.16, s.6.17]) from address Start covers
   --  Start .. Start + Qty - 1. It is Writable only when ONE declared range of the same
   --  Target holds every one of those addresses; a write straddling two adjacent ranges
   --  is refused (R-MB-16, conservative). A refused write is Address_Not_Writable,
   --  exception 02 (R-MB-12). Bounds are tested subtract-first: Qty <= Hi - Start + 1.

   function In_Range
     (R      : Lovelace_Mb_Policy_Shape_Pkg.Write_Range;
      Target : Lovelace_Mb_Policy_Shape_Pkg.Write_Target;
      Start  : Lovelace_Mb_Policy_Shape_Pkg.Item_Address;
      Qty    : Lovelace_Mb_Policy_Shape_Pkg.Write_Quantity) return Boolean is
     (R.Target = Target and then Start >= R.Lo and then Qty <= R.Hi - Start + 1)
     with Post => In_Range'Result
                    = (R.Target = Target and then R.Lo <= Start and then Start + Qty - 1 <= R.Hi)
                  and then (if In_Range'Result
                            then (for all A in Start .. Start + Qty - 1 => A >= R.Lo and then A <= R.Hi));

   function Writable
     (T      : Lovelace_Mb_Policy_Shape_Pkg.Policy_Table;
      Target : Lovelace_Mb_Policy_Shape_Pkg.Write_Target;
      Start  : Lovelace_Mb_Policy_Shape_Pkg.Item_Address;
      Qty    : Lovelace_Mb_Policy_Shape_Pkg.Write_Quantity) return Boolean is
     (for some I in 1 .. T.Range_Count => In_Range (T.Ranges (I), Target, Start, Qty))
     with Post => (if Writable'Result
                   then (for some I in 1 .. T.Range_Count =>
                           T.Ranges (I).Target = Target
                           and then (for all A in Start .. Start + Qty - 1 =>
                                       A >= T.Ranges (I).Lo and then A <= T.Ranges (I).Hi)))
                  and then Writable'Result
                    = (for some I in 1 .. T.Range_Count =>
                         T.Ranges (I).Target = Target
                         and then T.Ranges (I).Lo <= Start
                         and then Start + Qty - 1 <= T.Ranges (I).Hi)
                  and then (if Writable'Result then Start + Qty <= 65_536);

end Lovelace_Mb_Write_Range_Pkg;
