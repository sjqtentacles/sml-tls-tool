fun main () =
  let val ok = Tests.run ()
  in if ok then OS.Process.exit OS.Process.success
     else OS.Process.exit OS.Process.failure
  end
