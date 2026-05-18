{
  "targets": [
    {
      "target_name": "addon",
      "sources": [
        "addon.cpp",
        "rules/helpers.cpp",
        "rules/shell-composition.cpp",
        "rules/process-control.cpp",
        "rules/file-destruction.cpp",
        "rules/package-manager.cpp",
        "rules/sensitive-paths.cpp",
        "rules/self-disabling.cpp"
      ],
      "include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"],
      "dependencies": ["<!(node -p \"require('node-addon-api').gyp\")"],
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
      "cflags_cc": ["-std=c++17"]
    }
  ]
}
