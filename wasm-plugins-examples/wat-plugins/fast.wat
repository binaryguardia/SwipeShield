(module
  ;; fast.wat — a minimal SwipeShield plugin written in WebAssembly Text.
  ;; Demonstrates the WASI stdout contract: writes a PluginResponse JSON
  ;; verdict and exits. Response is read by the host and folded into the
  ;; decision engine.
  ;;
  ;; Build: wat2wasm fast.wat -o dist/fast.wasm   (wabt)
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "{\"verdicts\":[{\"rule_id\":\"WASM-WAT-001\",\"message\":\"blocked by wat plugin\",\"action\":\"block\",\"score\":0.9}]}")
  (func (export "_start")
    ;; iovec = { buf = 8, len = 104 }  (data occupies bytes 8..112)
    (i32.store (i32.const 0) (i32.const 8))
    (i32.store (i32.const 4) (i32.const 104))
    ;; nwritten at 128 (outside the data region)
    (i32.store (i32.const 128) (i32.const 1))
    (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 128))))
)
