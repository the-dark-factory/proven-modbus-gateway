with Lovelace_Mb_Pdu_Fields_Pkg;
with Lovelace_Mb_Fc_Catalog_Pkg;
with Lovelace_Mb_Pdu_Dispatch_Pkg;
with Lovelace_Mb_Pdu_View_Pkg;
with Lovelace_Mb_Policy_Shape_Pkg;
with Lovelace_Mb_Gate_Refusal_Pkg;
with Lovelace_Mb_Allow_Fc_Pkg;
with Lovelace_Mb_Write_Effect_Pkg;
with Lovelace_Mb_Write_Range_Pkg;
with Lovelace_Mb_Value_Limit_Pkg;
with Lovelace_Mb_Rate_Window_Pkg;
with Lovelace_Mb_Sequence_Pkg;

package Lovelace_Mb_Gate_Decide_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind;
   use type Lovelace_Mb_Policy_Shape_Pkg.Write_Target;
   use type Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms;
   use type Lovelace_Mb_Gate_Refusal_Pkg.Gate_Verdict;

   --  The water-gateway policy gate's decision (wave 3): one Pdu_Ok request P (1 .. N) from
   --  master Slot, judged against the site's policy table T, the per-slot rate states, the
   --  per-rule sequence states and the time Now (read once by the edge, R-MB-17). The tests
   --  run in this order and the first that fails names the verdict (R-MB-12):
   --  Unknown_Master (slot 0, R-MB-18, R-MB-20); Function_Not_Allowed; then, for a write only
   --  (FC5, 6, 15, 16, 22, 23 [APP s.6.5 .. s.6.17]): Address_Not_Writable (R-MB-16);
   --  Mask_On_Limited (FC22 on a register a value limit or a sequence rule names, R-MB-13,
   --  R-MB-30); Value_Below_Limit or Value_Above_Limit; Rate_Exceeded; Forbidden_Sequence.
   --  A read that is allowed always passes: rate and sequence rules are for writes only
   --  (R-MB-31). Decide reads nothing but its parameters (Global => null), so the same
   --  inputs always give the same verdict. THE PRODUCT THEOREM is its Post: a passed write is
   --  allowed, lies in one declared range, and no value it writes lies outside a declared
   --  limit of its register.

   --  [R-MB-30] A register named by either step of a used sequence rule.
   function Sequence_Names
     (T : Lovelace_Mb_Policy_Shape_Pkg.Policy_Table;
      A : Lovelace_Mb_Policy_Shape_Pkg.Item_Address) return Boolean is
     (for some I in 1 .. T.Sequence_Count =>
        (T.Sequences (I).Trigger_Step.Target = Lovelace_Mb_Policy_Shape_Pkg.Register_Target
         and then T.Sequences (I).Trigger_Step.Location = A)
        or else (T.Sequences (I).Then_Step.Target = Lovelace_Mb_Policy_Shape_Pkg.Register_Target
                 and then T.Sequences (I).Then_Step.Location = A));

   --  [R-MB-13, R-MB-30] FC22 on a register with a value limit or named by a sequence rule.
   function Mask_Refused
     (T : Lovelace_Mb_Policy_Shape_Pkg.Policy_Table;
      P : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes;
      N : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length) return Boolean is
     (Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Mask_Write_Fc
      and then (Lovelace_Mb_Value_Limit_Pkg.Has_Limit (T, Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N))
                or else Sequence_Names (T, Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N))))
     with Pre => Lovelace_Mb_Pdu_Dispatch_Pkg.Request_Ok (P, N)
                 and then Lovelace_Mb_Write_Effect_Pkg.Writes_Anything (P);

   --  Every stored time is at or before Now (a monotonic clock keeps this true).
   function Stored_Times_Ok
     (Rates : Lovelace_Mb_Rate_Window_Pkg.Rate_States;
      Seqs  : Lovelace_Mb_Sequence_Pkg.Seq_States;
      Now   : Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms) return Boolean is
     ((for all S in Lovelace_Mb_Policy_Shape_Pkg.Known_Slot => Now >= Rates (S).Window_Start)
      and then (for all I in Lovelace_Mb_Policy_Shape_Pkg.Sequence_Index => Now >= Seqs (I).Trigger_Ms));

   --  The write rules, in order, for an allowed write from a known slot.
   function Write_Verdict
     (T     : Lovelace_Mb_Policy_Shape_Pkg.Policy_Table;
      Slot  : Lovelace_Mb_Policy_Shape_Pkg.Known_Slot;
      P     : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes;
      N     : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length;
      Rates : Lovelace_Mb_Rate_Window_Pkg.Rate_States;
      Seqs  : Lovelace_Mb_Sequence_Pkg.Seq_States;
      Now   : Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms) return Lovelace_Mb_Gate_Refusal_Pkg.Gate_Verdict is
     (if not Lovelace_Mb_Write_Range_Pkg.Writable
               (T, Lovelace_Mb_Write_Effect_Pkg.Target_Of (P),
                Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N), Lovelace_Mb_Write_Effect_Pkg.Write_Qty (P, N))
      then Lovelace_Mb_Gate_Refusal_Pkg.Address_Not_Writable
      elsif Mask_Refused (T, P, N)
      then Lovelace_Mb_Gate_Refusal_Pkg.Mask_On_Limited
      elsif not Lovelace_Mb_Value_Limit_Pkg.Values_Ok
                  (T, Lovelace_Mb_Write_Effect_Pkg.Target_Of (P),
                   Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N), Lovelace_Mb_Write_Effect_Pkg.Write_Qty (P, N),
                   Lovelace_Mb_Write_Effect_Pkg.Values_Of (P, N))
      then (if Lovelace_Mb_Value_Limit_Pkg.Below_Any
                 (T, Lovelace_Mb_Write_Effect_Pkg.Target_Of (P),
                  Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N), Lovelace_Mb_Write_Effect_Pkg.Write_Qty (P, N),
                  Lovelace_Mb_Write_Effect_Pkg.Values_Of (P, N))
            then Lovelace_Mb_Gate_Refusal_Pkg.Value_Below_Limit
            else Lovelace_Mb_Gate_Refusal_Pkg.Value_Above_Limit)
      elsif not Lovelace_Mb_Rate_Window_Pkg.Rate_Ok (Rates (Slot), Now, T.Rates (Slot))
      then Lovelace_Mb_Gate_Refusal_Pkg.Rate_Exceeded
      elsif Lovelace_Mb_Sequence_Pkg.Any_Sequence_Hit
              (T, Seqs, Now, Lovelace_Mb_Write_Effect_Pkg.Target_Of (P),
               Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N), Lovelace_Mb_Write_Effect_Pkg.Write_Qty (P, N),
               Lovelace_Mb_Write_Effect_Pkg.Values_Of (P, N))
      then Lovelace_Mb_Gate_Refusal_Pkg.Forbidden_Sequence
      else Lovelace_Mb_Gate_Refusal_Pkg.Gate_Pass)
     with Pre => Lovelace_Mb_Pdu_Dispatch_Pkg.Request_Ok (P, N)
                 and then Lovelace_Mb_Write_Effect_Pkg.Writes_Anything (P)
                 and then Stored_Times_Ok (Rates, Seqs, Now);

   --  The gate's verdict on one Pdu_Ok request.
   function Decide
     (T     : Lovelace_Mb_Policy_Shape_Pkg.Policy_Table;
      Slot  : Lovelace_Mb_Policy_Shape_Pkg.Master_Slot;
      P     : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes;
      N     : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length;
      Rates : Lovelace_Mb_Rate_Window_Pkg.Rate_States;
      Seqs  : Lovelace_Mb_Sequence_Pkg.Seq_States;
      Now   : Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms) return Lovelace_Mb_Gate_Refusal_Pkg.Gate_Verdict is
     (if Slot = 0
      then Lovelace_Mb_Gate_Refusal_Pkg.Unknown_Master
      elsif not Lovelace_Mb_Allow_Fc_Pkg.Fc_Allowed (T, Slot, Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P))
      then Lovelace_Mb_Gate_Refusal_Pkg.Function_Not_Allowed
      elsif not Lovelace_Mb_Write_Effect_Pkg.Writes_Anything (P)
      then Lovelace_Mb_Gate_Refusal_Pkg.Gate_Pass
      else Write_Verdict (T, Slot, P, N, Rates, Seqs, Now))
     with Global => null,
          Pre => Lovelace_Mb_Pdu_Dispatch_Pkg.Request_Ok (P, N)
                 and then Stored_Times_Ok (Rates, Seqs, Now),
          Post => (if Slot = 0 then Decide'Result = Lovelace_Mb_Gate_Refusal_Pkg.Unknown_Master)
                  and then (if Decide'Result = Lovelace_Mb_Gate_Refusal_Pkg.Gate_Pass
                            then Slot /= 0
                                 and then Lovelace_Mb_Allow_Fc_Pkg.Fc_Allowed
                                            (T, Slot, Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P)))
                  and then (if Slot /= 0
                               and then Lovelace_Mb_Allow_Fc_Pkg.Fc_Allowed
                                          (T, Slot, Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P))
                               and then not Lovelace_Mb_Write_Effect_Pkg.Writes_Anything (P)
                            then Decide'Result = Lovelace_Mb_Gate_Refusal_Pkg.Gate_Pass)
                  and then (if Decide'Result = Lovelace_Mb_Gate_Refusal_Pkg.Gate_Pass
                               and then Lovelace_Mb_Write_Effect_Pkg.Writes_Anything (P)
                            then Lovelace_Mb_Write_Range_Pkg.Writable
                                   (T, Lovelace_Mb_Write_Effect_Pkg.Target_Of (P),
                                    Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N),
                                    Lovelace_Mb_Write_Effect_Pkg.Write_Qty (P, N))
                                 and then Lovelace_Mb_Value_Limit_Pkg.Values_Ok
                                   (T, Lovelace_Mb_Write_Effect_Pkg.Target_Of (P),
                                    Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N),
                                    Lovelace_Mb_Write_Effect_Pkg.Write_Qty (P, N),
                                    Lovelace_Mb_Write_Effect_Pkg.Values_Of (P, N)))
                  and then (if Decide'Result = Lovelace_Mb_Gate_Refusal_Pkg.Gate_Pass
                               and then Lovelace_Mb_Write_Effect_Pkg.Writes_Anything (P)
                               and then Lovelace_Mb_Pdu_View_Pkg.Has_Written_Values (P)
                               and then Lovelace_Mb_Write_Effect_Pkg.Target_Of (P)
                                          = Lovelace_Mb_Policy_Shape_Pkg.Register_Target
                            then (for all K in 1 .. Lovelace_Mb_Write_Effect_Pkg.Write_Qty (P, N) =>
                                    (for all I in 1 .. T.Limit_Count =>
                                       (if T.Limits (I).Register = Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N) + K - 1
                                        then Lovelace_Mb_Pdu_View_Pkg.Written_Value (P, N, K) >= T.Limits (I).Min
                                             and then Lovelace_Mb_Pdu_View_Pkg.Written_Value (P, N, K)
                                                        <= T.Limits (I).Max))))
                  and then (if Decide'Result = Lovelace_Mb_Gate_Refusal_Pkg.Gate_Pass
                               and then Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P) = Lovelace_Mb_Fc_Catalog_Pkg.Mask_Write_Fc
                            then not Lovelace_Mb_Value_Limit_Pkg.Has_Limit
                                       (T, Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N))
                                 and then not Sequence_Names (T, Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N)))
                  and then (if Decide'Result = Lovelace_Mb_Gate_Refusal_Pkg.Gate_Pass
                               and then Lovelace_Mb_Write_Effect_Pkg.Writes_Anything (P)
                            then Slot /= 0
                                 and then Lovelace_Mb_Rate_Window_Pkg.Rate_Ok (Rates (Slot), Now, T.Rates (Slot))
                                 and then not Lovelace_Mb_Sequence_Pkg.Any_Sequence_Hit
                                   (T, Seqs, Now, Lovelace_Mb_Write_Effect_Pkg.Target_Of (P),
                                    Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N),
                                    Lovelace_Mb_Write_Effect_Pkg.Write_Qty (P, N),
                                    Lovelace_Mb_Write_Effect_Pkg.Values_Of (P, N)))
                  and then (if Slot /= 0
                               and then Lovelace_Mb_Allow_Fc_Pkg.Fc_Allowed
                                          (T, Slot, Lovelace_Mb_Pdu_Dispatch_Pkg.Kind_Of (P))
                               and then Lovelace_Mb_Write_Effect_Pkg.Writes_Anything (P)
                               and then Lovelace_Mb_Write_Range_Pkg.Writable
                                          (T, Lovelace_Mb_Write_Effect_Pkg.Target_Of (P),
                                           Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N),
                                           Lovelace_Mb_Write_Effect_Pkg.Write_Qty (P, N))
                               and then not Mask_Refused (T, P, N)
                               and then Lovelace_Mb_Value_Limit_Pkg.Values_Ok
                                          (T, Lovelace_Mb_Write_Effect_Pkg.Target_Of (P),
                                           Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N),
                                           Lovelace_Mb_Write_Effect_Pkg.Write_Qty (P, N),
                                           Lovelace_Mb_Write_Effect_Pkg.Values_Of (P, N))
                               and then Lovelace_Mb_Rate_Window_Pkg.Rate_Ok (Rates (Slot), Now, T.Rates (Slot))
                               and then not Lovelace_Mb_Sequence_Pkg.Any_Sequence_Hit
                                              (T, Seqs, Now, Lovelace_Mb_Write_Effect_Pkg.Target_Of (P),
                                               Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N),
                                               Lovelace_Mb_Write_Effect_Pkg.Write_Qty (P, N),
                                               Lovelace_Mb_Write_Effect_Pkg.Values_Of (P, N))
                            then Decide'Result = Lovelace_Mb_Gate_Refusal_Pkg.Gate_Pass)
                  and then (if Decide'Result = Lovelace_Mb_Gate_Refusal_Pkg.Value_Below_Limit
                               or else Decide'Result = Lovelace_Mb_Gate_Refusal_Pkg.Value_Above_Limit
                            then Lovelace_Mb_Write_Effect_Pkg.Writes_Anything (P)
                                 and then (Decide'Result = Lovelace_Mb_Gate_Refusal_Pkg.Value_Below_Limit)
                                            = Lovelace_Mb_Value_Limit_Pkg.Below_Any
                                                (T, Lovelace_Mb_Write_Effect_Pkg.Target_Of (P),
                                                 Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N),
                                                 Lovelace_Mb_Write_Effect_Pkg.Write_Qty (P, N),
                                                 Lovelace_Mb_Write_Effect_Pkg.Values_Of (P, N)));

end Lovelace_Mb_Gate_Decide_Pkg;
