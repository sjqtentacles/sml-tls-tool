structure BogoArgs :> BOGO_ARGS =
struct
  exception BadArg of string

  datatype role = Client | Server

  type args = {
    role : role,
    port : int,
    minVersion : Word16.word option,
    maxVersion : Word16.word option,
    expectHandshakeSuccess : bool,
    expectError : string option,
    expectMsg : string option,
    rest : string list
  }

  val defaultArgs = {
    role = Client,
    port = 0,
    minVersion = NONE,
    maxVersion = NONE,
    expectHandshakeSuccess = false,
    expectError = NONE,
    expectMsg = NONE,
    rest = []
  }

  fun setRole a r = {role = r, port = #port a, minVersion = #minVersion a,
                     maxVersion = #maxVersion a,
                     expectHandshakeSuccess = #expectHandshakeSuccess a,
                     expectError = #expectError a,
                     expectMsg = #expectMsg a, rest = #rest a}
  fun setPort a p = {role = #role a, port = p, minVersion = #minVersion a,
                     maxVersion = #maxVersion a,
                     expectHandshakeSuccess = #expectHandshakeSuccess a,
                     expectError = #expectError a,
                     expectMsg = #expectMsg a, rest = #rest a}
  fun setMin a v = {role = #role a, port = #port a, minVersion = SOME v,
                    maxVersion = #maxVersion a,
                    expectHandshakeSuccess = #expectHandshakeSuccess a,
                    expectError = #expectError a,
                    expectMsg = #expectMsg a, rest = #rest a}
  fun setMax a v = {role = #role a, port = #port a, minVersion = #minVersion a,
                    maxVersion = SOME v,
                    expectHandshakeSuccess = #expectHandshakeSuccess a,
                    expectError = #expectError a,
                    expectMsg = #expectMsg a, rest = #rest a}
  fun setHS a = {role = #role a, port = #port a, minVersion = #minVersion a,
                 maxVersion = #maxVersion a,
                 expectHandshakeSuccess = true,
                 expectError = #expectError a,
                 expectMsg = #expectMsg a, rest = #rest a}
  fun setErr a e = {role = #role a, port = #port a, minVersion = #minVersion a,
                    maxVersion = #maxVersion a,
                    expectHandshakeSuccess = #expectHandshakeSuccess a,
                    expectError = SOME e,
                    expectMsg = #expectMsg a, rest = #rest a}
  fun setMsg a m = {role = #role a, port = #port a, minVersion = #minVersion a,
                    maxVersion = #maxVersion a,
                    expectHandshakeSuccess = #expectHandshakeSuccess a,
                    expectError = #expectError a,
                    expectMsg = SOME m, rest = #rest a}
  fun pushRest a s = {role = #role a, port = #port a, minVersion = #minVersion a,
                      maxVersion = #maxVersion a,
                      expectHandshakeSuccess = #expectHandshakeSuccess a,
                      expectError = #expectError a,
                      expectMsg = #expectMsg a, rest = s :: #rest a}

  (* Map BoGo version strings to the TLS version word. BoGo uses "TLS1",
     "TLS1.1", "TLS1.2", "TLS1.3". Explicit Word16.word: an unannotated 0wx
     literal defaults to the platform Word (32-bit MLton / 63-bit Poly/ML),
     which would silently mistype this against BOGO_ARGS's signature. *)
  fun parseVersion "TLS1.3" = (0wx0304 : Word16.word)
    | parseVersion "TLS1.2" = 0wx0303
    | parseVersion "TLS1.1" = 0wx0302
    | parseVersion "TLS1"   = 0wx0301
    | parseVersion v        = raise BadArg ("unknown version: " ^ v)

  fun parseArgs args =
    let
      fun go [] a = a
        | go ("-server" :: rest) a = go rest (setRole a Server)
        | go ("-client" :: rest) a = go rest (setRole a Client)
        | go ("-port" :: p :: rest) a =
            (* Parse via IntInf + fixed 32-bit bound so an oversized -port
               fails cleanly rather than raising Overflow under MLton's
               32-bit int (Poly/ML's 63-bit int would accept it) -- keeps
               behaviour identical across compilers. *)
            (case IntInf.fromString p of
                 SOME n => if n >= 0 andalso n <= 2147483647
                           then go rest (setPort a (IntInf.toInt n))
                           else raise BadArg ("bad -port: " ^ p)
               | NONE => raise BadArg ("bad -port: " ^ p))
        | go ("-min-version" :: v :: rest) a =
            go rest (setMin a (parseVersion v))
        | go ("-max-version" :: v :: rest) a =
            go rest (setMax a (parseVersion v))
        | go ("-expect-handshake-success" :: rest) a = go rest (setHS a)
        | go ("-expect-.*-error" :: v :: rest) a = go rest (setErr a v)
        | go ("-expect-msg" :: v :: rest) a = go rest (setMsg a v)
        | go (flag :: rest) a = go rest (pushRest a flag)  (* unknown: stash *)
    in go args defaultArgs end
end
