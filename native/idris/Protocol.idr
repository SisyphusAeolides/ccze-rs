module Protocol

%default total

public export
data Phase = Cold | Started | Authenticated | Bound | Ready

public export
data Event = Start | Authenticate | Bind | BecomeReady | Reset

public export
next : Phase -> Event -> Maybe Phase
next _ Reset = Just Cold
next Cold Start = Just Started
next Started Authenticate = Just Authenticated
next Authenticated Bind = Just Bound
next Bound BecomeReady = Just Ready
next _ _ = Nothing

public export
phaseCode : Phase -> Int
phaseCode Cold = 0
phaseCode Started = 1
phaseCode Authenticated = 2
phaseCode Bound = 3
phaseCode Ready = 4

public export
eventCode : Event -> Int
eventCode Start = 0
eventCode Authenticate = 1
eventCode Bind = 2
eventCode BecomeReady = 3
eventCode Reset = 4

resetAlwaysCold : (phase : Phase) -> next phase Reset = Just Cold
resetAlwaysCold Cold = Refl
resetAlwaysCold Started = Refl
resetAlwaysCold Authenticated = Refl
resetAlwaysCold Bound = Refl
resetAlwaysCold Ready = Refl

main : IO ()
main = pure ()
