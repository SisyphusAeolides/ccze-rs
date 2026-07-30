module Severity where

open import Agda.Builtin.Equality

data Nat : Set where
  zero : Nat
  suc : Nat -> Nat

data Severity : Set where
  trace debug info warn error fatal : Severity

rank : Severity -> Nat
rank trace = zero
rank debug = suc zero
rank info  = suc (suc zero)
rank warn  = suc (suc (suc zero))
rank error = suc (suc (suc (suc zero)))
rank fatal = suc (suc (suc (suc (suc zero))))

max : Nat -> Nat -> Nat
max zero y = y
max x zero = x
max (suc x) (suc y) = suc (max x y)

join : Severity -> Severity -> Severity
join trace y = y
join x trace = x
join debug debug = debug
join debug info = info
join debug warn = warn
join debug error = error
join debug fatal = fatal
join info debug = info
join info info = info
join info warn = warn
join info error = error
join info fatal = fatal
join warn debug = warn
join warn info = warn
join warn warn = warn
join warn error = error
join warn fatal = fatal
join error debug = error
join error info = error
join error warn = error
join error error = error
join error fatal = fatal
join fatal _ = fatal

join-idempotent : (severity : Severity) -> join severity severity ≡ severity
join-idempotent trace = refl
join-idempotent debug = refl
join-idempotent info = refl
join-idempotent warn = refl
join-idempotent error = refl
join-idempotent fatal = refl

join-commutative : (left right : Severity) -> join left right ≡ join right left
join-commutative trace trace = refl
join-commutative trace debug = refl
join-commutative trace info = refl
join-commutative trace warn = refl
join-commutative trace error = refl
join-commutative trace fatal = refl
join-commutative debug trace = refl
join-commutative debug debug = refl
join-commutative debug info = refl
join-commutative debug warn = refl
join-commutative debug error = refl
join-commutative debug fatal = refl
join-commutative info trace = refl
join-commutative info debug = refl
join-commutative info info = refl
join-commutative info warn = refl
join-commutative info error = refl
join-commutative info fatal = refl
join-commutative warn trace = refl
join-commutative warn debug = refl
join-commutative warn info = refl
join-commutative warn warn = refl
join-commutative warn error = refl
join-commutative warn fatal = refl
join-commutative error trace = refl
join-commutative error debug = refl
join-commutative error info = refl
join-commutative error warn = refl
join-commutative error error = refl
join-commutative error fatal = refl
join-commutative fatal trace = refl
join-commutative fatal debug = refl
join-commutative fatal info = refl
join-commutative fatal warn = refl
join-commutative fatal error = refl
join-commutative fatal fatal = refl
