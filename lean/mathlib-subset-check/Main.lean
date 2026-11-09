import Lean

/-!
# Mathlib subset checker

Checks that `lean/mathlib-subset` is a faithful subset of upstream Mathlib and Batteries, as
pinned by this package's `lake-manifest.json`.

The subset and upstream environments are both imported from the same module names. Every
declaration from a subset module must then:

* exist upstream, in the same module, with the same kind and number of universe parameters;
* have the same type and, for definitions, the same value, up to eta and universe parameter
  names, after replacing every proof subterm with a placeholder (so the subset may prove
  things differently);
* have the same reducibility, instance priority, and class/structure shape;
* depend only on the standard axioms.

Theorems only need matching statements. Theorems with internal names (auxiliary proofs) and
generated equation lemmas are not compared. Other declarations with internal names (such as
matchers) need not exist upstream: a definition referring to one only matches if upstream
refers to an identically named, matching declaration. The values of metaprograms (definitions
whose upstream type mentions the `Lean` namespace) are not compared, since they only affect
elaboration and every elaborated term is itself checked; everything else about them is.

Usage: `lake exe mathlib-subset-check <path to the built mathlib-subset package>`
-/

open Lean Meta

namespace MathlibSubsetCheck

/-- Library roots of the subset package. -/
def roots : List String := ["Mathlib", "Batteries"]

def allowedAxioms : List Name := [``propext, ``Quot.sound, ``Classical.choice]

/-- Module names of all `.lean` files under the subset's library roots. -/
def subsetModules (dir : System.FilePath) : IO (Array Name) := do
  let base := dir.components.length
  let mut mods := #[]
  for root in roots do
    let rootDir := dir / root
    unless ← rootDir.isDir do
      continue
    for p in ← rootDir.walkDir do
      if p.extension == some "lean" then
        let comps := (p.withExtension "").components.drop base
        mods := mods.push <| comps.foldl .str .anonymous
  return mods.qsort Name.lt

def loadEnv (sp : SearchPath) (mods : Array Name) : IO Environment := do
  searchPathRef.set sp
  importModules (mods.map fun m => { module := m }) {}

def runIn (env : Environment) (x : MetaM α) : IO α :=
  let ctx : Core.Context :=
    { fileName := "<mathlib-subset-check>", fileMap := default, maxHeartbeats := 0 }
  (x.run' {} {}).toIO' ctx { env }

def moduleOf? (env : Environment) (n : Name) : Option Name := do
  let idx ← env.getModuleIdxFor? n
  env.header.moduleNames[idx.toNat]?

/-- Replace every maximal proof subterm by a placeholder constant, and eta-reduce. -/
def eraseProofs (e : Expr) : MetaM Expr :=
  Meta.transform e
    (pre :=
      fun e => do
        if e.isSort || e.isForall then return .continue
        let isPrf ←
          try
            isProof e
          catch _ =>
            pure false
        return if isPrf then .done (mkConst `«proof») else .continue)
    (post := fun e => return .done e.eta)

/-- Attributes recorded in environment extensions. They are read from the imported module
data directly, because `importModules (loadExts := true)` would run the imported modules'
initializers, which cannot be done for both environments in one process. -/
structure EnvAttrs where
  instances : NameMap String := {}
  reducibility : NameMap ReducibilityStatus := {}
  classes : NameMap (Array Nat) := {}

def envAttrs (env : Environment) : EnvAttrs :=
  Id.run do
    let mut a : EnvAttrs := {}
    for i in [0:env.header.moduleNames.size] do
      for e in Meta.instanceExtension.ext.getModuleEntries env i (level := .private) do
        let (e, scope) :=
          match e with
          | .global e => (e, "")
          | .scoped ns e => (e, s!" scoped in {ns}")
        if let some n := e.globalName? then
          a := { a with instances := a.instances.insert n s!"{e.priority}{scope}" }
      for e in reducibilityExtraExt.ext.getModuleEntries env i (level := .private) do
        match e with
        | .global (n, r) | .scoped _ (n, r) =>
            a := { a with reducibility := a.reducibility.insert n r }
      for e in classExtension.getModuleEntries env i (level := .private) do
        a := { a with classes := a.classes.insert e.name e.outParams }
    return a

/-- Structural equality ignoring binder names and metadata, but not binder info. -/
partial def same : Expr → Expr → Bool
  | .mdata _ a, b => same a b
  | a, .mdata _ b => same a b
  | .app f a, .app g b => same f g && same a b
  | .lam _ t b i, .lam _ t' b' i' => i == i' && same t t' && same b b'
  | .forallE _ t b i, .forallE _ t' b' i' => i == i' && same t t' && same b b'
  | .letE _ t v b _, .letE _ t' v' b' _ => same t t' && same v v' && same b b'
  | .proj s i e, .proj s' i' e' => s == s' && i == i' && same e e'
  | a, b => a == b

/-- What is compared between the subset and upstream versions of a declaration. -/
structure Summary where
  module : Name
  kind : String
  numLevelParams : Nat
  type : Expr
  value? : Option Expr := none
  shape : String := ""
  attrs : String := ""
deriving Inhabited

def summarize (attrs : EnvAttrs) (n : Name) : MetaM Summary := do
  let env ← getEnv
  let ci ← getConstInfo n
  let module := (moduleOf? env n).getD .anonymous
  -- Universe parameter names are irrelevant to users; only their number and order matter.
  let levels := ci.levelParams.mapIdx fun i _ => mkLevelParam (.num `u i)
  let normalize (e : Expr) :=
    return (← eraseProofs e).instantiateLevelParams ci.levelParams levels
  let type ← normalize ci.type
  let reducibility := attrs.reducibility.find? n |>.getD (getReducibilityStatusCore env n)
  let attrs :=
    s!"reducibility={repr reducibility} instance={attrs.instances.find? n} \
    classOutParams={attrs.classes.find? n} \
    structureFields={if isStructure env n then toString (getStructureFields env n) else "-"}"
  let base : Summary :=
    { module, kind := "", numLevelParams := ci.levelParams.length, type, attrs }
  match ci with
  | .defnInfo d =>
      let value ← normalize d.value
      return {
        base with
          kind := "def", value? := some value, shape := s!"safety={repr d.safety}"
      }
  | .thmInfo _ => return { base with kind := "theorem" }
  | .opaqueInfo o =>
      let value ← normalize o.value
      return {
        base with
          kind := "opaque", value? := some value, shape := s!"unsafe={o.isUnsafe}"
      }
  | .inductInfo i =>
      return {
        base with
          kind := "inductive"
          shape :=
            s!"params={i.numParams} indices={i.numIndices} all={i.all} ctors={i.ctors} \
        nested={i.numNested} rec={i.isRec} unsafe={i.isUnsafe} reflexive={i.isReflexive}"
      }
  | .ctorInfo c =>
      return {
        base with
          kind := "constructor"
          shape :=
            s!"induct={c.induct} cidx={c.cidx} params={c.numParams} fields={c.numFields} \
        unsafe={c.isUnsafe}"
      }
  | .recInfo r =>
      return {
        base with
          kind := "recursor"
          shape := s!"all={r.all} params={r.numParams} indices={r.numIndices} \
        motives={r.numMotives} minors={r.numMinors} k={r.k} unsafe={r.isUnsafe}"
      }
  | .quotInfo _ => return { base with kind := "quot" }
  | .axiomInfo _ => return { base with kind := "axiom" }

/-- Equation lemmas are generated on demand, in whichever module first needs them. -/
def isGeneratedEqn : Name → Bool
  | .str _ s =>
      Meta.isEqnReservedNameSuffix s
      || s == Meta.unfoldThmSuffix
      || s == Meta.eqUnfoldThmSuffix
  | _ => false

/-- Differences between the subset and upstream summaries of a declaration. -/
def diff (sub up : Summary) : IO (List String) := do
  let mut out := []
  if sub.module != up.module then
    out := s!"declared in {sub.module}, but upstream in {up.module}" :: out
  if sub.kind != up.kind then
    return [s!"is a {sub.kind}, but upstream a {up.kind}"]
  if sub.numLevelParams != up.numLevelParams then
    out :=
      s!"has {sub.numLevelParams} universe parameters, but upstream {up.numLevelParams}"
      :: out
  if !same sub.type up.type then
    out :=
      s!"type differs from upstream:\n  subset:   {sub.type}\n  upstream: {up.type}"
      :: out
  match sub.value?, up.value? with
  | some v, some v' =>
      if !same v v' then
        out := s!"value differs from upstream:\n  subset:   {v}\n  upstream: {v'}" :: out
  | _, _ => pure ()
  if sub.shape != up.shape then
    out := s!"shape `{sub.shape}` differs from upstream `{up.shape}`" :: out
  if sub.kind != "theorem" && sub.attrs != up.attrs then
    out := s!"attributes `{sub.attrs}` differ from upstream `{up.attrs}`" :: out
  return out.reverse

/-- Metaprograms only affect elaboration, so their values are not compared. -/
def isMeta (type : Expr) : Bool :=
  type.getUsedConstants.any (·.getRoot == `Lean)

def main (args : List String) : IO UInt32 := do
  let [dir] := args
  |
    IO.eprintln "usage: mathlib-subset-check <path to the built mathlib-subset package>"
    return 2
  let dir ← IO.FS.realPath dir
  let mods ← subsetModules dir
  if mods.isEmpty then
    IO.eprintln s!"no modules found under {dir}"
    return 2
  let modSet : NameSet := mods.foldl (·.insert ·) {}
  let builtin ← getBuiltinSearchPath (← findSysroot)
  -- The subset environment sees only the subset's build output and the Lean core.
  let subEnv ← loadEnv ([dir / ".lake" / "build" / "lib" / "lean"] ++ builtin) mods
  -- Upstream comes from `LEAN_PATH`, which `lake exe` sets to this package's dependencies.
  let upEnv ← loadEnv (← addSearchPathFromEnv builtin) mods
  let subAttrs := envAttrs subEnv
  let upAttrs := envAttrs upEnv
  let names :=
    subEnv.constants.map₁.fold (init := #[])
      fun acc n _ =>
        match moduleOf? subEnv n with
        | some m => if modSet.contains m then acc.push n else acc
        | none => acc
  let names := names.qsort Name.lt
  let mut errors : Array String := #[]
  let mut checked := 0
  let mut metaprograms := 0
  let mut subsetOnly := 0
  for n in names do
    let some ci := subEnv.find? n | unreachable!
    let axioms ← runIn subEnv (collectAxioms n)
    for ax in axioms do
      unless allowedAxioms.contains ax do
        errors := errors.push s!"{n}: depends on axiom {ax}"
    let internal := n.isInternalDetail || isPrivateName n
    if (internal || isGeneratedEqn n) && ci matches .thmInfo _ then
      subsetOnly := subsetOnly + 1
      continue
    unless upEnv.contains n do
      if internal then
        subsetOnly := subsetOnly + 1
      else
        errors := errors.push s!"{n}: not found upstream"
      continue
    let mut sub ← runIn subEnv (summarize subAttrs n)
    let mut up ← runIn upEnv (summarize upAttrs n)
    -- The types are still compared, so this only applies if upstream is a metaprogram too.
    if isMeta up.type then
      sub := { sub with value? := none }
      up := { up with value? := none }
      metaprograms := metaprograms + 1
    for d in ← diff sub up do
      errors := errors.push s!"{n}: {d}"
    checked := checked + 1
  IO.println
    s!"{mods.size} modules, {names.size} declarations: {checked} match upstream \
    ({metaprograms} metaprograms, values not compared), {subsetOnly} internal (not compared)"
  if errors.isEmpty then
    IO.println "OK"
    return 0
  for e in errors do
    IO.eprintln e
  IO.eprintln s!"{errors.size} problems found"
  return 1

end MathlibSubsetCheck

def main (args : List String) : IO UInt32 :=
  MathlibSubsetCheck.main args
