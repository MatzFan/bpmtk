address = &h7FFDF000
MsgBox "Hello from inside the InjectScript.dll"
scriptengine.Output("Some text output from inside the InjectScript.dll")
scriptengine.Suspend
MsgBox "Suspended"
MsgBox scriptengine.Peek(address)
scriptengine.Poke address, 67
MsgBox scriptengine.Peek(address)
MsgBox scriptengine.Peek(0)
scriptengine.Poke 0, 67
scriptengine.Resume
