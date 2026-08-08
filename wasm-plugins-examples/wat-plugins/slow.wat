(module
  ;; slow.wat — a deliberately misbehaving plugin used to verify the host
  ;; enforces its execution timeout. It busy-loops, calling a function every
  ;; iteration so the host runtime can interrupt it when the context expires.
  ;;
  ;; Build: wat2wasm slow.wat -o dist/slow.wasm   (wabt)
  (func $tick)
  (func (export "_start")
    (loop $l
      call $tick
      br $l))
)
