function hookLoadLibrary () {
  var f_dlopen = Module.findExportByName(null, "__loader_dlopen")
  Interceptor.attach(f_dlopen, {
    onEnter: function (args) {
      this.soname = args[0].readCString()
      this.find = false
      //console.log("dlopen:" + this.soname)
      if(this.soname.indexOf("chinese") != -1)
      {
        this.find = true
      }
    },
    onLeave: function (retval) {
        if(this.find)
        {
            inject()
        }
    }
  })

  var f_android_dlopen_ext_base = Module.findExportByName(null, "android_dlopen_ext")
  Interceptor.attach(f_android_dlopen_ext_base, {
    onEnter: function (args) {
      this.soname = args[0].readCString()
      this.find = false
      //console.log("android_dlopen_ext:" + this.soname)
        if(this.soname.indexOf("chinese") != -1)
        {
          this.find = true
        }
    },
    onLeave: function (retval) {
        if(this.find)
        {
            inject()
        }
    }
  })
}

function inject () {
  var dlopenPtr = Module.findExportByName(null, 'dlopen');
  var dlopen = new NativeFunction(dlopenPtr, 'pointer', ['pointer', 'int']);
  var soPath = "/data/local/tmp/libnativelib.so"; // trace 模块路径
  var soPathPtr = Memory.allocUtf8String(soPath);
  console.log("inject libnativelib.so")
  dlopen(soPathPtr, 2);
}

function attachInject () {
  inject()
}

setImmediate(hookLoadLibrary);