with Lovelace_Mb_Pdu_Fields_Pkg;
with Lovelace_Mb_Pdu_Dispatch_Pkg;
with Lovelace_Mb_Policy_Shape_Pkg;
with Lovelace_Mb_Gate_Refusal_Pkg;
with Lovelace_Mb_Write_Effect_Pkg;
with Lovelace_Mb_Rate_Window_Pkg;
with Lovelace_Mb_Sequence_Pkg;

package Lovelace_Mb_Gate_Next_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms;
   use type Lovelace_Mb_Gate_Refusal_Pkg.Gate_Verdict;
   use type Lovelace_Mb_Rate_Window_Pkg.Rate_State;
   use type Lovelace_Mb_Sequence_Pkg.Seq_State;

   --  The water-gateway policy gate's state after one decision (wave 3, R-MB-17): the rate
   --  state of each known master slot and the trigger state of each sequence rule, held by
   --  the policy-gate edge and passed here as a value. Only a PASSED WRITE changes it: its
   --  slot's rate window counts it (Next_Rate) and every rule whose Trigger step it writes is
   --  armed at Now (Next_Triggers). A refused request, and a read, leave the state exactly as
   --  it was (R-MB-31), so a refusal never consumes the rate or arms a sequence. Every stored
   --  time stays at or before Now and every count within its slot's Max_Writes, so with a
   --  monotonic clock the next Decide's precondition holds again. The Pre on a passed write
   --  (slot known, Rate_Ok) is what gate-decide's Post gives for a Gate_Pass.

   type Gate_State is record
      Rates : Lovelace_Mb_Rate_Window_Pkg.Rate_States;
      Seqs  : Lovelace_Mb_Sequence_Pkg.Seq_States;
   end record;

   function Initial_State return Gate_State is
     ((Rates => (others => Lovelace_Mb_Rate_Window_Pkg.Initial_Rate),
       Seqs  => (others => Lovelace_Mb_Sequence_Pkg.Initial_Seq)));

   function State_Timely
     (S   : Gate_State;
      Now : Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms) return Boolean is
     ((for all J in Lovelace_Mb_Policy_Shape_Pkg.Known_Slot => Now >= S.Rates (J).Window_Start)
      and then (for all I in Lovelace_Mb_Policy_Shape_Pkg.Sequence_Index => Now >= S.Seqs (I).Trigger_Ms));

   function Counts_Bounded
     (T : Lovelace_Mb_Policy_Shape_Pkg.Policy_Table;
      S : Gate_State) return Boolean is
     (for all J in Lovelace_Mb_Policy_Shape_Pkg.Known_Slot => S.Rates (J).Count <= T.Rates (J).Max_Writes);

   function Next_State
     (T       : Lovelace_Mb_Policy_Shape_Pkg.Policy_Table;
      S       : Gate_State;
      Verdict : Lovelace_Mb_Gate_Refusal_Pkg.Gate_Verdict;
      Slot    : Lovelace_Mb_Policy_Shape_Pkg.Master_Slot;
      P       : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Bytes;
      N       : Lovelace_Mb_Pdu_Fields_Pkg.Pdu_Length;
      Now     : Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms) return Gate_State is
     (if Verdict = Lovelace_Mb_Gate_Refusal_Pkg.Gate_Pass and then Lovelace_Mb_Write_Effect_Pkg.Writes_Anything (P)
      then (Rates => (S.Rates with delta Slot
                        => Lovelace_Mb_Rate_Window_Pkg.Next_Rate (S.Rates (Slot), Now, T.Rates (Slot))),
            Seqs  => Lovelace_Mb_Sequence_Pkg.Next_Triggers
                       (T, S.Seqs, Now, True, Lovelace_Mb_Write_Effect_Pkg.Target_Of (P),
                        Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N), Lovelace_Mb_Write_Effect_Pkg.Write_Qty (P, N),
                        Lovelace_Mb_Write_Effect_Pkg.Values_Of (P, N)))
      else S)
     with Pre => Lovelace_Mb_Policy_Shape_Pkg.Valid_Table (T)
                 and then Lovelace_Mb_Pdu_Dispatch_Pkg.Request_Ok (P, N)
                 and then State_Timely (S, Now)
                 and then (if Verdict = Lovelace_Mb_Gate_Refusal_Pkg.Gate_Pass
                              and then Lovelace_Mb_Write_Effect_Pkg.Writes_Anything (P)
                           then Slot /= 0
                                and then Lovelace_Mb_Rate_Window_Pkg.Rate_Ok (S.Rates (Slot), Now, T.Rates (Slot))),
          Post => (if Verdict /= Lovelace_Mb_Gate_Refusal_Pkg.Gate_Pass
                      or else not Lovelace_Mb_Write_Effect_Pkg.Writes_Anything (P)
                   then Next_State'Result = S)
                  and then State_Timely (Next_State'Result, Now)
                  and then (if Counts_Bounded (T, S) then Counts_Bounded (T, Next_State'Result))
                  and then (for all J in Lovelace_Mb_Policy_Shape_Pkg.Known_Slot =>
                              (if Next_State'Result.Rates (J) /= S.Rates (J)
                               then Verdict = Lovelace_Mb_Gate_Refusal_Pkg.Gate_Pass and then J = Slot))
                  and then (for all I in Lovelace_Mb_Policy_Shape_Pkg.Sequence_Index =>
                              (if Next_State'Result.Seqs (I) /= S.Seqs (I)
                               then Verdict = Lovelace_Mb_Gate_Refusal_Pkg.Gate_Pass
                                    and then Next_State'Result.Seqs (I).Trigger_Seen
                                    and then Next_State'Result.Seqs (I).Trigger_Ms = Now))
                  and then (if Verdict = Lovelace_Mb_Gate_Refusal_Pkg.Gate_Pass
                               and then Lovelace_Mb_Write_Effect_Pkg.Writes_Anything (P)
                            then Slot /= 0
                                 and then Next_State'Result.Rates (Slot).Count >= 1
                                 and then Next_State'Result.Rates (Slot).Count <= T.Rates (Slot).Max_Writes
                                 and then (if Now - S.Rates (Slot).Window_Start
                                                >= Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms (T.Rates (Slot).Window_Ms)
                                           then Next_State'Result.Rates (Slot).Window_Start = Now
                                                and then Next_State'Result.Rates (Slot).Count = 1
                                           else Next_State'Result.Rates (Slot).Window_Start
                                                  = S.Rates (Slot).Window_Start
                                                and then Next_State'Result.Rates (Slot).Count
                                                           = S.Rates (Slot).Count + 1)
                                 and then (for all I in 1 .. T.Sequence_Count =>
                                             (if Lovelace_Mb_Sequence_Pkg.Is_Trigger
                                                   (T.Sequences (I), Lovelace_Mb_Write_Effect_Pkg.Target_Of (P),
                                                    Lovelace_Mb_Write_Effect_Pkg.Write_Start (P, N),
                                                    Lovelace_Mb_Write_Effect_Pkg.Write_Qty (P, N),
                                                    Lovelace_Mb_Write_Effect_Pkg.Values_Of (P, N))
                                              then Next_State'Result.Seqs (I).Trigger_Seen
                                                   and then Next_State'Result.Seqs (I).Trigger_Ms = Now)));

end Lovelace_Mb_Gate_Next_Pkg;
