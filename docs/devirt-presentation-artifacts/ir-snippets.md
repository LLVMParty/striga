# Intermediate IR snippets

## resolver-built-call.ll

```llvm
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114032), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114040), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114048), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114056), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114064), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114072), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114080), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114088), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114096), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114104), align 1
  call void @lifted_0x140016000(ptr %state, ptr @RAM)
  unreachable
}
```

## resolver-inlined-hook-call.ll

```llvm
  %226 = zext i1 %225 to i8
  store i8 %226, ptr %zf.i, align 1, !tbaa !39, !alias.scope !47, !noalias !50
  %227 = lshr i64 %207, 63
  %228 = trunc i64 %227 to i1
  %229 = zext i1 %228 to i8
  store i8 %229, ptr %sf.i, align 1, !tbaa !41, !alias.scope !47, !noalias !50
  %230 = xor i64 %205, %207
  %231 = xor i64 %206, %207
  %232 = and i64 %230, %231
  %233 = and i64 %232, -9223372036854775808
  %234 = icmp ne i64 %233, 0
  %235 = zext i1 %234 to i8
  store i8 %235, ptr %of.i, align 1, !tbaa !43, !alias.scope !47, !noalias !50
  %236 = load i64, ptr %state, align 4, !tbaa !31, !alias.scope !47, !noalias !50
  call void @__striga_jmp(i64 %236), !noalias !50
  unreachable
}
```

## resolver-hook-rewritten-return.ll

```llvm
  %230 = xor i64 %205, %207
  %231 = xor i64 %206, %207
  %232 = and i64 %230, %231
  %233 = and i64 %232, -9223372036854775808
  %234 = icmp ne i64 %233, 0
  %235 = zext i1 %234 to i8
  store i8 %235, ptr %of.i, align 1, !tbaa !43, !alias.scope !47, !noalias !50
  %236 = load i64, ptr %state, align 4, !tbaa !31, !alias.scope !47, !noalias !50
  %237 = insertvalue %TraceResult_140016000 { i8 1, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i8 undef, i8 undef, i8 undef, i8 undef, i8 undef, i8 undef }, i64 %236, 1
  %rax_snap = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 0
  %238 = load i64, ptr %rax_snap, align 4
  %239 = insertvalue %TraceResult_140016000 %237, i64 %238, 2
  %rbx_snap = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 1
  %240 = load i64, ptr %rbx_snap, align 4
  %241 = insertvalue %TraceResult_140016000 %239, i64 %240, 3
  %rcx_snap = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 2
  %242 = load i64, ptr %rcx_snap, align 4
  %243 = insertvalue %TraceResult_140016000 %241, i64 %242, 4
  %rdx_snap = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 3
  %244 = load i64, ptr %rdx_snap, align 4
  %245 = insertvalue %TraceResult_140016000 %243, i64 %244, 5
  %rsi_snap = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 4
  %246 = load i64, ptr %rsi_snap, align 4
  %247 = insertvalue %TraceResult_140016000 %245, i64 %246, 6
  %rdi_snap = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 5
  %248 = load i64, ptr %rdi_snap, align 4
  %249 = insertvalue %TraceResult_140016000 %247, i64 %248, 7
  %rsp_snap = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 6
  %250 = load i64, ptr %rsp_snap, align 4
```

## resolver-optimized-target.ll

```llvm
  %29 = insertvalue %TraceResult_140016000 %28, i128 0, 33
  %30 = insertvalue %TraceResult_140016000 %29, i128 0, 34
  %31 = insertvalue %TraceResult_140016000 %30, i128 0, 35
  %32 = insertvalue %TraceResult_140016000 %31, i128 0, 36
  %33 = insertvalue %TraceResult_140016000 %32, i128 0, 37
  %34 = insertvalue %TraceResult_140016000 %33, i128 0, 38
  %35 = insertvalue %TraceResult_140016000 %34, i128 0, 39
  %36 = insertvalue %TraceResult_140016000 %35, i128 0, 40
  %37 = insertvalue %TraceResult_140016000 %36, i128 0, 41
  %38 = insertvalue %TraceResult_140016000 %37, i128 0, 42
  %39 = insertvalue %TraceResult_140016000 %38, i128 0, 43
  %40 = insertvalue %TraceResult_140016000 %39, i128 0, 44
  %41 = insertvalue %TraceResult_140016000 %40, i128 0, 45
  %42 = insertvalue %TraceResult_140016000 %41, i128 0, 46
  %43 = insertvalue %TraceResult_140016000 %42, i128 0, 47
  %44 = insertvalue %TraceResult_140016000 %43, i128 0, 48
  %45 = insertvalue %TraceResult_140016000 %44, i128 0, 49
  %46 = insertvalue %TraceResult_140016000 %45, i128 0, 50
  %47 = insertvalue %TraceResult_140016000 %46, i8 0, 51
  %48 = insertvalue %TraceResult_140016000 %47, i8 0, 52
  %49 = insertvalue %TraceResult_140016000 %48, i8 0, 53
  %50 = insertvalue %TraceResult_140016000 %49, i8 0, 54
  %51 = insertvalue %TraceResult_140016000 %50, i8 0, 55
  %52 = insertvalue %TraceResult_140016000 %51, i8 0, 56
  ret %TraceResult_140016000 %52
}
```

## jcc-resolver-select.ll

```llvm
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1113992), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114000), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114008), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114016), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114024), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114032), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114040), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114048), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114056), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114064), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114072), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114080), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114088), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114096), align 1
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114104), align 1
  store i64 %87, ptr getelementptr (i8, ptr @RAM, i64 1113416), align 1, !alias.scope !23, !noalias !26
  %88 = and i64 %66, 64
  %.not = icmp eq i64 %88, 0
  %89 = select i1 %.not, i64 5368802751, i64 5368802682
  %90 = insertvalue %TraceResult_14001676b { i8 1, i64 5368799338, i64 5368799338, i64 4294965437, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i64 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i128 undef, i8 undef, i8 undef, i8 undef, i8 undef, i8 undef, i8 undef }, i64 %rcx_entry_7089, 4
  %91 = insertvalue %TraceResult_14001676b %90, i64 0, 5
  %92 = insertvalue %TraceResult_14001676b %91, i64 0, 6
  %93 = insertvalue %TraceResult_14001676b %92, i64 0, 7
  %94 = insertvalue %TraceResult_14001676b %93, i64 1113424, 8
  %95 = insertvalue %TraceResult_14001676b %94, i64 0, 9
  %96 = insertvalue %TraceResult_14001676b %95, i64 0, 10
  %97 = insertvalue %TraceResult_14001676b %96, i64 0, 11
  %98 = insertvalue %TraceResult_14001676b %97, i64 0, 12
  %99 = insertvalue %TraceResult_14001676b %98, i64 0, 13
  %100 = insertvalue %TraceResult_14001676b %99, i64 0, 14
  %101 = insertvalue %TraceResult_14001676b %100, i64 %89, 15
  %102 = insertvalue %TraceResult_14001676b %101, i64 5368709120, 16
  %103 = insertvalue %TraceResult_14001676b %102, i64 1113792, 17
  %104 = insertvalue %TraceResult_14001676b %103, i64 1114112, 18
  %105 = insertvalue %TraceResult_14001676b %104, i128 0, 19
  %106 = insertvalue %TraceResult_14001676b %105, i128 0, 20
  %107 = insertvalue %TraceResult_14001676b %106, i128 0, 21
  %108 = insertvalue %TraceResult_14001676b %107, i128 0, 22
  %109 = insertvalue %TraceResult_14001676b %108, i128 0, 23
```

## recovered-skeleton-switch.ll

```llvm
  store i64 0, ptr getelementptr (i8, ptr @RAM, i64 1114104), align 1
  call void @lifted_0x14001676b(ptr %state, ptr @RAM)
  %r13_node_267_14001676b2 = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 13
  %0 = load i64, ptr %r13_node_267_14001676b2, align 4
  switch i64 %0, label %unresolved [
    i64 5368802751, label %node_268_14001606a
    i64 5368802682, label %node_269_14001606a
  ]

node_268_14001606a:                               ; preds = %node_267_14001676b
  %rax_node_268_14001606a = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 0
  store i64 5368799338, ptr %rax_node_268_14001606a, align 4
  %rbx_node_268_14001606a = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 1
  store i64 4294965437, ptr %rbx_node_268_14001606a, align 4
  %rdx_node_268_14001606a = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 3
  store i64 0, ptr %rdx_node_268_14001606a, align 4
  %rsi_node_268_14001606a = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 4
```

## recovered-round8-first-compare.ll

```llvm
  store i64 1113824, ptr getelementptr (i8, ptr @RAM, i64 1113776), align 1, !alias.scope !147, !noalias !150
  store i64 1113824, ptr getelementptr (i8, ptr @RAM, i64 1113552), align 1, !alias.scope !152, !noalias !155
  %5 = add i32 %4, -1859
  %6 = icmp ult i32 %4, 1859
  %7 = trunc i32 %5 to i8
  %8 = lshr i8 %7, 4
  %9 = xor i8 %8, %7
  %10 = lshr i8 %9, 2
  %11 = xor i8 %9, %10
  %12 = lshr i8 %11, 1
  %13 = xor i8 %11, %12
  %14 = xor i32 %5, %4
  %15 = icmp eq i32 %4, 1859
  %16 = sub i32 1858, %4
  %17 = and i32 %16, %4
  %18 = shl i8 %13, 2
  %19 = and i8 %18, 4
  %20 = zext i1 %6 to i8
  %21 = or disjoint i8 %19, %20
  %22 = xor i8 %21, 6
  %.lobit19570 = and i32 %14, 16
  %23 = zext nneg i8 %22 to i32
  %24 = or disjoint i32 %.lobit19570, %23
  %25 = zext nneg i32 %24 to i64
  %26 = select i1 %15, i64 64, i64 0
  %27 = or i64 %26, %25
  %28 = lshr i32 %5, 24
  %29 = and i32 %28, 128
  %30 = lshr i32 %17, 20
  %31 = and i32 %30, 2048
  %32 = or disjoint i32 %29, %31
  %33 = zext nneg i32 %32 to i64
  %34 = or disjoint i64 %27, %33
  store i64 %34, ptr getelementptr (i8, ptr @RAM, i64 1113780), align 1, !alias.scope !157, !noalias !160
  store i64 %34, ptr getelementptr (i8, ptr @RAM, i64 1113424), align 1, !alias.scope !162, !noalias !165
  store i32 %5, ptr getelementptr (i8, ptr @RAM, i64 1113552), align 1, !alias.scope !167, !noalias !170
  store i64 %34, ptr getelementptr (i8, ptr @RAM, i64 1113784), align 1, !alias.scope !172, !noalias !175
  store i64 %34, ptr getelementptr (i8, ptr @RAM, i64 1113416), align 1, !alias.scope !177, !noalias !180
  %.not = icmp samesign ult i64 %27, 64
  %35 = select i1 %.not, i64 5368802747, i64 5368802678
  %36 = getelementptr i8, ptr @RAM, i64 %35
  %trunc = trunc i64 %35 to i32
  switch i32 %trunc, label %unresolved [
    i32 1073835451, label %node_285_1400162b1
    i32 1073835382, label %node_269_14001606a
```

## recovered-residual-membership.ll

```llvm
  store i64 1113824, ptr getelementptr (i8, ptr @RAM, i64 1113776), align 1, !alias.scope !82, !noalias !85
  store i64 1113824, ptr getelementptr (i8, ptr @RAM, i64 1113552), align 1, !alias.scope !87, !noalias !90
  %5 = add i32 %4, -1859
  %6 = icmp ult i32 %4, 1859
  %7 = trunc i32 %5 to i8
  %8 = lshr i8 %7, 4
  %9 = xor i8 %8, %7
  %10 = lshr i8 %9, 2
  %11 = xor i8 %10, %9
  %12 = lshr i8 %11, 1
  %13 = xor i8 %12, %11
  %14 = xor i32 %5, %4
  %15 = icmp eq i32 %4, 1859
  %16 = sub i32 1858, %4
  %17 = and i32 %16, %4
  %18 = shl i8 %13, 2
  %19 = and i8 %18, 4
  %20 = zext i1 %6 to i8
  %21 = or disjoint i8 %19, %20
  %22 = xor i8 %21, 6
  %.lobit19570 = and i32 %14, 16
  %23 = zext nneg i8 %22 to i32
  %24 = or disjoint i32 %.lobit19570, %23
  %25 = zext nneg i32 %24 to i64
  %26 = select i1 %15, i64 64, i64 0
  %27 = or i64 %26, %25
  %28 = lshr i32 %5, 24
  %29 = and i32 %28, 128
  %30 = lshr i32 %17, 20
  %31 = and i32 %30, 2048
  %32 = or disjoint i32 %31, %29
  %33 = zext nneg i32 %32 to i64
  %34 = or disjoint i64 %27, %33
  store i64 %34, ptr getelementptr (i8, ptr @RAM, i64 1113780), align 1, !alias.scope !92, !noalias !95
  store i64 %34, ptr getelementptr (i8, ptr @RAM, i64 1113424), align 1, !alias.scope !97, !noalias !100
  store i32 %5, ptr getelementptr (i8, ptr @RAM, i64 1113552), align 1, !alias.scope !102, !noalias !105
  store i64 %34, ptr getelementptr (i8, ptr @RAM, i64 1113784), align 1, !alias.scope !107, !noalias !110
  store i64 %34, ptr getelementptr (i8, ptr @RAM, i64 1113416), align 1, !alias.scope !112, !noalias !115
  %.not = icmp samesign ult i64 %27, 64
  %35 = select i1 %.not, i64 5368802747, i64 5368802678
  %36 = getelementptr i8, ptr @RAM, i64 %35
  %trunc = trunc i64 %35 to i32
  switch i32 %trunc, label %unresolved [
    i32 1073835451, label %node_285_1400162b1
    i32 1073835382, label %node_269_14001606a
  ]

node_269_14001606a:                               ; preds = %entry
  store i32 1, ptr getelementptr (i8, ptr @RAM, i64 1113804), align 1, !alias.scope !117, !noalias !120
  br label %node_285_1400162b1

node_285_1400162b1:                               ; preds = %entry, %node_269_14001606a
  %37 = phi i32 [ 0, %entry ], [ 1, %node_269_14001606a ]
  store i32 282213, ptr getelementptr (i8, ptr @RAM, i64 1113800), align 1, !alias.scope !122, !noalias !125
  store i64 2, ptr getelementptr (i8, ptr @RAM, i64 1113768), align 1, !alias.scope !127, !noalias !130
  store i64 1113824, ptr getelementptr (i8, ptr @RAM, i64 1113776), align 1, !alias.scope !132, !noalias !135
  store i64 1113824, ptr getelementptr (i8, ptr @RAM, i64 1113552), align 1, !alias.scope !137, !noalias !140
  %38 = add i32 %4, -2418
  %39 = icmp ult i32 %4, 2418
  %40 = trunc i32 %38 to i8
  %41 = lshr i8 %40, 4
  %42 = xor i8 %41, %40
  %43 = lshr i8 %42, 2
  %44 = xor i8 %43, %42
  %45 = lshr i8 %44, 1
  %46 = xor i8 %45, %44
  %47 = xor i32 %38, %4
  %48 = icmp eq i32 %4, 2418
  %49 = sub i32 2417, %4
  %50 = and i32 %49, %4
  %51 = shl i8 %46, 2
  %52 = and i8 %51, 4
  %53 = zext i1 %39 to i8
  %54 = or disjoint i8 %52, %53
  %55 = xor i8 %54, 6
  %56 = and i32 %47, 16
  %57 = zext nneg i8 %55 to i32
  %58 = or disjoint i32 %56, %57
  %59 = xor i32 %58, 16
  %60 = zext nneg i32 %59 to i64
  %61 = select i1 %48, i64 64, i64 0
  %62 = or i64 %61, %60
  %63 = lshr i32 %38, 24
  %64 = and i32 %63, 128
  %65 = lshr i32 %50, 20
```

## recovered-final.ll

```llvm
; clean BinaryShield recovery; VM dispatch, bytecode, and RAM model removed
define i64 @recovered_binaryshield(i64 %rcx) {
entry:
  %x = trunc i64 %rcx to i32
  %cmp0 = icmp eq i32 %x, 1859
  %cmp1 = icmp eq i32 %x, 2418
  %cmp2 = icmp eq i32 %x, 1638
  %cmp3 = icmp eq i32 %x, 299902
  %cmp4 = icmp eq i32 %x, 29763
  %or1 = or i1 %cmp0, %cmp1
  %or2 = or i1 %or1, %cmp2
  %or3 = or i1 %or2, %cmp3
  %or4 = or i1 %or3, %cmp4
  %result = zext i1 %or4 to i64
  ret i64 %result
}
```
