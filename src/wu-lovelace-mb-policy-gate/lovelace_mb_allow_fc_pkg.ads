with Lovelace_Mb_Fc_Catalog_Pkg;
with Lovelace_Mb_Policy_Shape_Pkg;

package Lovelace_Mb_Allow_Fc_Pkg with SPARK_Mode, Pure is

   use type Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind;

   --  The per-slot function-code allowance of the water-gateway policy (wave 3, R-MB-12):
   --  a request is considered only when its master slot's Allow_Row admits its kind;
   --  otherwise the gate answers Function_Not_Allowed (exception 01 ILLEGAL FUNCTION,
   --  [APP s.7]). Unsupported_Fc (every code out of scope, R-MB-10) is never allowed,
   --  whatever the table says. Under Valid_Table, slot 0 (the unknown peer) allows nothing.

   function Fc_Allowed
     (T    : Lovelace_Mb_Policy_Shape_Pkg.Policy_Table;
      Slot : Lovelace_Mb_Policy_Shape_Pkg.Master_Slot;
      Kind : Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind) return Boolean is
     (Kind /= Lovelace_Mb_Fc_Catalog_Pkg.Unsupported_Fc and then T.Allow (Slot) (Kind))
     with Post => (if Kind = Lovelace_Mb_Fc_Catalog_Pkg.Unsupported_Fc then not Fc_Allowed'Result)
                  and then (if Slot = 0 and then Lovelace_Mb_Policy_Shape_Pkg.Valid_Table (T)
                            then not Fc_Allowed'Result)
                  and then (if Fc_Allowed'Result then T.Allow (Slot) (Kind))
                  and then (if T.Allow (Slot) (Kind) and then Kind in Lovelace_Mb_Fc_Catalog_Pkg.Public_Kind
                            then Fc_Allowed'Result);

end Lovelace_Mb_Allow_Fc_Pkg;
