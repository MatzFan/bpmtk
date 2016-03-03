#/*
#	Makefile for bpmtk
#	Source code put in public domain by Didier Stevens, no Copyright
#	https://DidierStevens.com
#	Use at your own risk
#
# Developed with Borland's free C++ compiler: http://cc.codegear.com/Free.aspx?id=24778
# You need to install the MS Platform SDK for BCC: http://sourceforge.net/projects/bccsdk/
# I decompress it in the BORLAND\bccsdk_0_0_7_1 directory, next to BORLAND\BCC55
#
#	Shortcomings, or todo's ;-)
#	
#	History:
#	2008/01/23: Start
#	2008/01/28: added hook-cmd
#	2008/02/10: added rc, sign
# 2008/02/12: added manifest
# 2008/02/13: added InjectScript
# 2008/02/14: added AddResource.exe
# 2008/02/17: added output.c
# 2008/02/19: added scriptengine.rc
# 2008/02/22: added plugin
# 2008/02/26: restructered for release
# 2008/06/24: added bpmtk.dll
# 2008/06/24: added hook-iexplore.dll
# 2008/06/30: added notepad-keylogger.dll
# 2008/07/30: added cmd-rootkit.dll
# 2009/09/30: added hook-createprocess.dll
# 2009/11/04: added hook-createprocess.rc
#*/


BCC = $(MAKEDIR)\..
CFLAGS = -DINCLUDE_RESOURCE -I$(BCC)\include -I$(BCC)\..\bccsdk_0_0_7_1\include -L$(BCC)\lib;$(BCC)\lib\psdk
TARGETS_SIGN = bpmtk.exe
TARGETS_NOSIGN = bpmtk.dll
TARGETS_INJECT_SCRIPT = InjectScript.dll
TARGETS_DEMO = hello-world-getversion.exe dummy.dll hook-hello.dll hook-test.dll hook-cmd.dll plugin.dll hook-iexplore.dll notepad-keylogger.dll cmd-rootkit.dll hook-createprocess.dll
TARGETS_RESEARCH_S1 = 
TARGETS = $(TARGETS_SIGN) $(TARGETS_NOSIGN) $(TARGETS_INJECT_SCRIPT) $(TARGETS_DEMO) $(TARGETS_RESEARCH_S1)

.c.dll:
      $(CC) -WD $(CFLAGS) $&.c

.autodepend

AllFiles: $(TARGETS) 

#TARGETS_SIGN

bpmtk.exe: bpmtk.c bpmtk.h bpmtk.res psutils.obj parser.obj psutils.h parser.h output.obj
      $(CC) $(CFLAGS) $&.c psutils.obj parser.obj output.obj

iat.c: iat.h

bpmtk.res: bpmtk.rc bpmtk.h bpmtk.exe.manifest

psutils.c: psutils.h output.h

parser.c: parser.h

output.c: output.h

#TARGETS_NOSIGN

bpmtk.dll: bpmtk.c bpmtk.h bpmtk.res psutils.obj parser.obj psutils.h parser.h output.obj
      $(CC) -WD $(CFLAGS) $&.c psutils.obj parser.obj output.obj

#TARGETS_INJECT_SCRIPT

injectscript.dll: injectscript.c scriptengine.h scriptengine.obj scriptengine.res
      $(CC) -WD $(CFLAGS) $&.c scriptengine.obj

scriptengine.c: scriptengine.h

injectscript.c: injectscript.h scriptengine.h

scriptengine.res: scriptengine.rc scriptengine.tlb

#TARGETS_DEMO

hook-hello.dll: hook-hello.c iat.obj psutils.obj output.obj
      $(CC) -WD $(CFLAGS) $&.c iat.obj psutils.obj output.obj

hook-test.dll: hook-test.c iat.obj psutils.obj output.obj
      $(CC) -WD $(CFLAGS) $&.c iat.obj psutils.obj output.obj

hook-cmd.dll: hook-cmd.c iat.obj psutils.obj output.obj
      $(CC) -WD $(CFLAGS) $&.c iat.obj psutils.obj output.obj

hook-iexplore.dll: hook-iexplore.c iat.obj psutils.obj output.obj
      $(CC) -WD $(CFLAGS) $&.c iat.obj psutils.obj output.obj

notepad-keylogger.dll: notepad-keylogger.c iat.obj psutils.obj output.obj
      $(CC) -WD $(CFLAGS) $&.c iat.obj psutils.obj output.obj

cmd-rootkit.dll: cmd-rootkit.c iat.obj psutils.obj output.obj
      $(CC) -WD $(CFLAGS) $&.c iat.obj psutils.obj output.obj

hook-createprocess.res: scriptengine.rc

hook-createprocess.dll: hook-createprocess.c iat.obj psutils.obj output.obj hook-createprocess.res
      $(CC) -WD $(CFLAGS) $&.c iat.obj psutils.obj output.obj

#TARGETS_RESEARCH_S1

clean-up:
	del *.bak *.obj *.tds *.res
	
delete-targets:
	del $(TARGETS)

sign:
	$(MYDIRS)\bin\signtool sign /sha1 6450A4BC7E05364B89518F91E90E46161E7F0D6B /t http://timestamp.verisign.com/scripts/timstamp.dll $(TARGETS_SIGN)
	$(MYDIRS)\bin\signtool sign /sha1 6450A4BC7E05364B89518F91E90E46161E7F0D6B /t http://timestamp.verisign.com/scripts/timstamp.dll $(TARGETS_NOSIGN)
	$(MYDIRS)\bin\signtool sign /sha1 6450A4BC7E05364B89518F91E90E46161E7F0D6B /t http://timestamp.verisign.com/scripts/timstamp.dll hook-createprocess.dll
