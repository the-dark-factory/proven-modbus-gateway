with Lovelace_Mb_Fc_Catalog_Pkg;

package Lovelace_Mb_Policy_Shape_Pkg with SPARK_Mode, Pure is

   --  The water-gateway site policy (wave 3): the types of one site's policy table, with
   --  fixed capacities (R-MB-15): 16 master slots, 32 write ranges, 64 value limits,
   --  16 sequence rules. Slot 0 is the unknown peer (R-MB-18, R-MB-20) and may do nothing.
   --  Addresses and register values are the 16-bit fields of [APP s.4.4]: 0 .. 65535.
   --  A written coil value is 0 (OFF) or 1 (ON) [APP s.6.5, s.6.11].
   --  Written_Values holds the K-th written item at index K, K = 1 .. Quantity, for the
   --  address Start + K - 1; items past Quantity are never consulted.
   --  Clock_Ms is a monotonic millisecond count read once per request by the edge and
   --  passed as a value (R-MB-17); 64-bit, so it never wraps in service.
   --  Valid_Table is exactly: every used range Lo <= Hi, every used limit Min <= Max,
   --  no register with two limits, every rate rule within bounds (1 .. 1000 writes per
   --  1 .. 86_400_000 ms), every used sequence rule Within_Ms >= 1, and slot 0 allows no
   --  function. A table failing it is never loaded.

   subtype Master_Slot is Natural range 0 .. 16;
   subtype Known_Slot is Master_Slot range 1 .. 16;
   subtype Item_Address is Natural range 0 .. 65_535;
   subtype Item_Value is Natural range 0 .. 65_535;
   subtype Write_Quantity is Positive range 1 .. 1_968;

   type Written_Values is array (Write_Quantity) of Item_Value;

   type Write_Target is (Coil_Target, Register_Target);

   type Allow_Row is array (Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind) of Boolean;
   type Allow_Table is array (Master_Slot) of Allow_Row;

   type Write_Range is record
      Target : Write_Target;
      Lo     : Item_Address;
      Hi     : Item_Address;
   end record;

   subtype Range_Tally is Natural range 0 .. 32;
   subtype Range_Index is Positive range 1 .. 32;
   type Range_Array is array (Range_Index) of Write_Range;

   type Value_Limit is record
      Register : Item_Address;
      Min      : Item_Value;
      Max      : Item_Value;
   end record;

   subtype Limit_Tally is Natural range 0 .. 64;
   subtype Limit_Index is Positive range 1 .. 64;
   type Limit_Array is array (Limit_Index) of Value_Limit;

   type Rate_Rule is record
      Max_Writes : Natural;
      Window_Ms  : Natural;
   end record;

   type Rate_Rules is array (Known_Slot) of Rate_Rule;

   type Sequence_Step is record
      Target   : Write_Target;
      Location : Item_Address;
      Value    : Item_Value;
   end record;

   type Sequence_Rule is record
      Trigger_Step : Sequence_Step;
      Then_Step    : Sequence_Step;
      Within_Ms    : Natural;
   end record;

   subtype Sequence_Tally is Natural range 0 .. 16;
   subtype Sequence_Index is Positive range 1 .. 16;
   type Sequence_Array is array (Sequence_Index) of Sequence_Rule;

   type Policy_Table is record
      Allow          : Allow_Table;
      Range_Count    : Range_Tally;
      Ranges         : Range_Array;
      Limit_Count    : Limit_Tally;
      Limits         : Limit_Array;
      Rates          : Rate_Rules;
      Sequence_Count : Sequence_Tally;
      Sequences      : Sequence_Array;
   end record;

   type Clock_Ms is range 0 .. 2 ** 62;

   function Rate_Rule_Ok (R : Rate_Rule) return Boolean is
     (R.Max_Writes >= 1 and then R.Max_Writes <= 1_000
      and then R.Window_Ms >= 1 and then R.Window_Ms <= 86_400_000);

   function Ranges_Ordered (T : Policy_Table) return Boolean is
     (for all I in 1 .. T.Range_Count => T.Ranges (I).Lo <= T.Ranges (I).Hi);

   function Limits_Ordered (T : Policy_Table) return Boolean is
     (for all I in 1 .. T.Limit_Count => T.Limits (I).Min <= T.Limits (I).Max);

   function Limits_Distinct (T : Policy_Table) return Boolean is
     (for all I in 1 .. T.Limit_Count =>
        (for all J in I + 1 .. T.Limit_Count => T.Limits (I).Register /= T.Limits (J).Register));

   function Rates_Bounded (T : Policy_Table) return Boolean is
     (for all S in Known_Slot => Rate_Rule_Ok (T.Rates (S)));

   function Sequences_Timed (T : Policy_Table) return Boolean is
     (for all I in 1 .. T.Sequence_Count => T.Sequences (I).Within_Ms >= 1);

   function Slot_Zero_Closed (T : Policy_Table) return Boolean is
     (for all K in Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind => not T.Allow (0) (K));

   function Valid_Table (T : Policy_Table) return Boolean is
     (Ranges_Ordered (T)
      and then Limits_Ordered (T)
      and then Limits_Distinct (T)
      and then Rates_Bounded (T)
      and then Sequences_Timed (T)
      and then Slot_Zero_Closed (T))
     with Post => Valid_Table'Result
                    = ((for all I in 1 .. T.Range_Count => T.Ranges (I).Hi - T.Ranges (I).Lo >= 0)
                       and then (for all I in 1 .. T.Limit_Count => T.Limits (I).Max - T.Limits (I).Min >= 0)
                       and then (for all I in 1 .. T.Limit_Count =>
                                   (for all J in 1 .. T.Limit_Count =>
                                      (if I /= J then T.Limits (I).Register /= T.Limits (J).Register)))
                       and then (for all S in Known_Slot =>
                                   T.Rates (S).Max_Writes in 1 .. 1_000
                                   and then T.Rates (S).Window_Ms in 1 .. 86_400_000)
                       and then (for all I in 1 .. T.Sequence_Count => T.Sequences (I).Within_Ms /= 0)
                       and then (for all K in Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind =>
                                   T.Allow (0) (K) = False));

end Lovelace_Mb_Policy_Shape_Pkg;
