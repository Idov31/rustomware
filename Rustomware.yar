/*
   YARA Rule Set
   Author: Ido Veltzman
   Date: 2022-10-24
   Reference: https://github.com/Idov31/Rustomware
*/

rule rustomware {
   meta:
      description = "Rust ransomware example"
      author = "Ido Veltzman"
      reference = "https://github.com/Idov31/Rustomware"
      date = "2022-10-24"
   strings:
      $x1 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\v0.rs" fullword ascii
      $x2 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\legacy.rs" fullword ascii
      $s5 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\libaes-0.6.4\\src\\lib.rs" ascii
      $s6 = ".llvm.C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\lib.rs" fullword ascii
      $s7 = "uncategorized errorother errorout of memoryunexpected end of fileunsupportedoperation interruptedargument list too longinvalid f" ascii
      $s8 = "assertion failed: state_and_queue.addr() & STATE_MASK == RUNNINGOnce instance has previously been poisoned" fullword ascii
      $s9 = "toryoperation would blockentity already existsbroken pipenetwork downaddress not availableaddress in usenot connectedconnection " ascii
      $s10 = "Your files are encrypted by Rustsomware./README_Rustsomware.txt" fullword ascii
      $s11 = "lock count overflow in reentrant mutexlibrary\\std\\src\\sys_common\\remutex.rs" fullword ascii
      $s12 = "workFileHandleFilesystemLoopReadOnlyFilesystemDirectoryNotEmptyIsADirectoryNotADirectoryWouldBlockAlreadyExistsBrokenPipeNetwork" ascii
      $s13 = "drop of the panic payload panicked" fullword ascii
      $s14 = "Not enough arguments! Usage: rustsomware <encrypt|decrypt> <folder>" fullword ascii
      $s15 = "Unable to create keyed event handle: error " fullword ascii
      $s16 = "ssionDeniedNotFound*I/O error: operation failed to complete synchronously" fullword ascii
      $s17 = "abortednetwork unreachablehost unreachableconnection resetconnection refusedpermission deniedentity not foundErrorkind" fullword ascii
      $s18 = "thread panicked while processing panic. aborting." fullword ascii
      $s19 = "keyed events not available" fullword ascii
      $s20 = "attempted to index str up to maximum usize" fullword ascii

      $op0 = { 0f 82 25 ff ff ff b9 02 }
      $op1 = { 3d 00 08 00 00 0f 82 15 ff ff ff 3d 00 00 01 00 }
      $op2 = { 48 83 d9 00 e9 02 ff ff ff 66 90 4a 8d 0c 36 31 }
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}
