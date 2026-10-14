with Lovelace_Mb_Policy_Shape_Pkg;

package Lovelace_Mb_Sequence_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Policy_Shape_Pkg.Write_Target;
   use type Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms;

   --  The forbidden-sequence rule of the water-gateway policy (wave 3): a rule names a
   --  Trigger step and a Then step (target, address, written value) and Within_Ms. Once a
   --  PASSED write has written the Trigger step, a write of the Then step within Within_Ms
   --  of it (inclusive) is refused: Forbidden_Sequence, exception 04 (R-MB-12), e.g. inlet
   --  valve open (coil 1 := 1) within 30_000 ms of pump stop (coil 0 := 0) (R-MB-19).
   --  A single write that holds both steps (e.g. FC15 over coils 0 .. 1) also hits.
   --  Trigger state is site-wide per rule (R-MB-17); only a passed write arms it. Time is a
   --  parameter; Now >= Trigger_Ms (subtract-first). Values (K) is the value written to
   --  Start + K - 1 (a coil as 0 or 1).

   type Seq_State is record
      Trigger_Seen : Boolean;
      Trigger_Ms   : Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms;
   end record;

   type Seq_States is array (Lovelace_Mb_Policy_Shape_Pkg.Sequence_Index) of Seq_State;

   function Initial_Seq return Seq_State is
     ((Trigger_Seen => False, Trigger_Ms => 0));

   function Step_Hit
     (S      : Lovelace_Mb_Policy_Shape_Pkg.Sequence_Step;
      Target : Lovelace_Mb_Policy_Shape_Pkg.Write_Target;
      Start  : Lovelace_Mb_Policy_Shape_Pkg.Item_Address;
      Qty    : Lovelace_Mb_Policy_Shape_Pkg.Write_Quantity;
      Values : Lovelace_Mb_Policy_Shape_Pkg.Written_Values) return Boolean is
     (S.Target = Target
      and then S.Location >= Start
      and then S.Location - Start < Qty
      and then Values (S.Location - Start + 1) = S.Value)
     with Post => Step_Hit'Result
                    = (S.Target = Target
                       and then (for some K in 1 .. Qty =>
                                   Start + K - 1 = S.Location and then Values (K) = S.Value));

   function Is_Trigger
     (Rule   : Lovelace_Mb_Policy_Shape_Pkg.Sequence_Rule;
      Target : Lovelace_Mb_Policy_Shape_Pkg.Write_Target;
      Start  : Lovelace_Mb_Policy_Shape_Pkg.Item_Address;
      Qty    : Lovelace_Mb_Policy_Shape_Pkg.Write_Quantity;
      Values : Lovelace_Mb_Policy_Shape_Pkg.Written_Values) return Boolean is
     (Step_Hit (Rule.Trigger_Step, Target, Start, Qty, Values));

   function Hits_Then
     (Rule   : Lovelace_Mb_Policy_Shape_Pkg.Sequence_Rule;
      Target : Lovelace_Mb_Policy_Shape_Pkg.Write_Target;
      Start  : Lovelace_Mb_Policy_Shape_Pkg.Item_Address;
      Qty    : Lovelace_Mb_Policy_Shape_Pkg.Write_Quantity;
      Values : Lovelace_Mb_Policy_Shape_Pkg.Written_Values) return Boolean is
     (Step_Hit (Rule.Then_Step, Target, Start, Qty, Values));

   function Sequence_Hit
     (Rule   : Lovelace_Mb_Policy_Shape_Pkg.Sequence_Rule;
      State  : Seq_State;
      Now    : Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms;
      Target : Lovelace_Mb_Policy_Shape_Pkg.Write_Target;
      Start  : Lovelace_Mb_Policy_Shape_Pkg.Item_Address;
      Qty    : Lovelace_Mb_Policy_Shape_Pkg.Write_Quantity;
      Values : Lovelace_Mb_Policy_Shape_Pkg.Written_Values) return Boolean is
     (Hits_Then (Rule, Target, Start, Qty, Values)
      and then ((State.Trigger_Seen
                 and then Now - State.Trigger_Ms <= Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms (Rule.Within_Ms))
                or else Is_Trigger (Rule, Target, Start, Qty, Values)))
     with Pre => Now >= State.Trigger_Ms,
          Post => (if State.Trigger_Seen
                      and then Now - State.Trigger_Ms <= Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms (Rule.Within_Ms)
                      and then Rule.Then_Step.Target = Target
                      and then (for some K in 1 .. Qty =>
                                  Start + K - 1 = Rule.Then_Step.Location
                                  and then Values (K) = Rule.Then_Step.Value)
                   then Sequence_Hit'Result)
                  and then (if Is_Trigger (Rule, Target, Start, Qty, Values)
                               and then Hits_Then (Rule, Target, Start, Qty, Values)
                            then Sequence_Hit'Result)
                  and then (if Sequence_Hit'Result then Hits_Then (Rule, Target, Start, Qty, Values))
                  and then (if not Is_Trigger (Rule, Target, Start, Qty, Values)
                               and then (not State.Trigger_Seen
                                         or else Now - State.Trigger_Ms
                                                   > Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms (Rule.Within_Ms))
                            then not Sequence_Hit'Result);

   function Any_Sequence_Hit
     (T      : Lovelace_Mb_Policy_Shape_Pkg.Policy_Table;
      States : Seq_States;
      Now    : Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms;
      Target : Lovelace_Mb_Policy_Shape_Pkg.Write_Target;
      Start  : Lovelace_Mb_Policy_Shape_Pkg.Item_Address;
      Qty    : Lovelace_Mb_Policy_Shape_Pkg.Write_Quantity;
      Values : Lovelace_Mb_Policy_Shape_Pkg.Written_Values) return Boolean is
     (for some I in 1 .. T.Sequence_Count =>
        Sequence_Hit (T.Sequences (I), States (I), Now, Target, Start, Qty, Values))
     with Pre => (for all I in Lovelace_Mb_Policy_Shape_Pkg.Sequence_Index => Now >= States (I).Trigger_Ms),
          Post => (if (for some I in 1 .. T.Sequence_Count =>
                         States (I).Trigger_Seen
                         and then Now - States (I).Trigger_Ms
                                    <= Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms (T.Sequences (I).Within_Ms)
                         and then Hits_Then (T.Sequences (I), Target, Start, Qty, Values))
                   then Any_Sequence_Hit'Result)
                  and then (if Any_Sequence_Hit'Result
                            then (for some I in 1 .. T.Sequence_Count =>
                                    Hits_Then (T.Sequences (I), Target, Start, Qty, Values)));

   function Next_Trigger
     (Rule   : Lovelace_Mb_Policy_Shape_Pkg.Sequence_Rule;
      State  : Seq_State;
      Now    : Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms;
      Passed : Boolean;
      Target : Lovelace_Mb_Policy_Shape_Pkg.Write_Target;
      Start  : Lovelace_Mb_Policy_Shape_Pkg.Item_Address;
      Qty    : Lovelace_Mb_Policy_Shape_Pkg.Write_Quantity;
      Values : Lovelace_Mb_Policy_Shape_Pkg.Written_Values) return Seq_State is
     (if Passed and then Is_Trigger (Rule, Target, Start, Qty, Values)
      then (Trigger_Seen => True, Trigger_Ms => Now)
      else State)
     with Pre => Now >= State.Trigger_Ms,
          Post => (if not Passed then Next_Trigger'Result = State)
                  and then (if not Is_Trigger (Rule, Target, Start, Qty, Values)
                            then Next_Trigger'Result = State)
                  and then (if Passed and then Is_Trigger (Rule, Target, Start, Qty, Values)
                            then Next_Trigger'Result.Trigger_Seen
                                 and then Next_Trigger'Result.Trigger_Ms = Now)
                  and then Next_Trigger'Result.Trigger_Ms <= Now;

   function Next_Triggers
     (T      : Lovelace_Mb_Policy_Shape_Pkg.Policy_Table;
      States : Seq_States;
      Now    : Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms;
      Passed : Boolean;
      Target : Lovelace_Mb_Policy_Shape_Pkg.Write_Target;
      Start  : Lovelace_Mb_Policy_Shape_Pkg.Item_Address;
      Qty    : Lovelace_Mb_Policy_Shape_Pkg.Write_Quantity;
      Values : Lovelace_Mb_Policy_Shape_Pkg.Written_Values) return Seq_States is
     ((for I in Lovelace_Mb_Policy_Shape_Pkg.Sequence_Index =>
         (if I <= T.Sequence_Count
          then Next_Trigger (T.Sequences (I), States (I), Now, Passed, Target, Start, Qty, Values)
          else States (I))))
     with Pre => (for all I in Lovelace_Mb_Policy_Shape_Pkg.Sequence_Index => Now >= States (I).Trigger_Ms),
          Post => (if not Passed then Next_Triggers'Result = States)
                  and then (for all I in Lovelace_Mb_Policy_Shape_Pkg.Sequence_Index =>
                              Next_Triggers'Result (I).Trigger_Ms <= Now)
                  and then (for all I in 1 .. T.Sequence_Count =>
                              (if Passed and then Is_Trigger (T.Sequences (I), Target, Start, Qty, Values)
                               then Next_Triggers'Result (I).Trigger_Seen
                                    and then Next_Triggers'Result (I).Trigger_Ms = Now
                               else Next_Triggers'Result (I) = States (I)));

end Lovelace_Mb_Sequence_Pkg;
