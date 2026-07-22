/*
 * il2cpp/api_defs.js — canonical IL2CPP public-API surface used for runtime
 * metadata traversal, plus non-allocating struct field readers.
 *
 * WHY THIS IS OBSERVATION-ONLY:
 *   IL2CPP has already decrypted global-metadata into process memory for its own
 *   use. We call ONLY the runtime's read-only enumeration API (get/enumerate),
 *   which reads that in-memory metadata. We do not decrypt, we do not extract
 *   keys, we do not write target memory. The API functions chosen below are all
 *   read-only accessors; none allocate target heap (so nothing to free, no
 *   mutation). il2cpp_type_get_name (which allocates) is intentionally AVOIDED —
 *   we derive type names via non-allocating class accessors instead.
 *
 * The set of functions and their C signatures are stable across IL2CPP metadata
 * v24..v29 (Unity 2018.4 .. 2022.3). Return-type/param handling is best-effort.
 */
(function () {
  var U = KS.utils;

  // name -> [retType, [argTypes...]] for NativeFunction construction.
  var SIG = {
    il2cpp_init:                    ['int',     ['pointer']],
    il2cpp_get_corlib:             ['pointer', []],
    il2cpp_domain_get:              ['pointer', []],
    il2cpp_domain_get_assemblies:   ['pointer', ['pointer', 'pointer']], // (domain, size_t* size) -> Il2CppAssembly**
    il2cpp_assembly_get_image:      ['pointer', ['pointer']],
    il2cpp_image_get_name:          ['pointer', ['pointer']],
    il2cpp_image_get_class_count:   ['uint32',  ['pointer']],
    il2cpp_image_get_class:         ['pointer', ['pointer', 'uint32']],
    il2cpp_class_get_name:          ['pointer', ['pointer']],
    il2cpp_class_get_namespace:     ['pointer', ['pointer']],
    il2cpp_class_get_methods:       ['pointer', ['pointer', 'pointer']], // (klass, void** iter) -> MethodInfo*
    il2cpp_class_get_method_from_name:['pointer',['pointer', 'pointer', 'int']],
    il2cpp_class_get_flags:         ['int',     ['pointer']],
    il2cpp_class_is_enum:           ['bool',    ['pointer']],
    il2cpp_class_get_parent:        ['pointer', ['pointer']],
    il2cpp_class_get_interface_count:['int',    ['pointer']],
    il2cpp_method_get_name:         ['pointer', ['pointer']],
    il2cpp_method_get_param_count:  ['uint32',  ['pointer']],
    il2cpp_method_get_param:        ['pointer', ['pointer', 'uint32']],
    il2cpp_method_get_param_name:   ['pointer', ['pointer', 'uint32']],
    il2cpp_method_get_return_type:  ['pointer', ['pointer']],
    il2cpp_method_get_flags:        ['uint32',  ['pointer', 'pointer']],
    il2cpp_type_get_type:           ['int',     ['pointer']],
    il2cpp_type_get_class_or_element_class: ['pointer', ['pointer']]
  };

  // The order below approximates the IL2CPP toolchain's export emission order.
  // Used by the (opt-in) export-index auto-mapper in api_locator.js. It is a
  // HEURISTIC aid, validated behaviorally before use — never trusted blindly.
  var CANONICAL_ORDER_HINT = [
    'il2cpp_init', 'il2cpp_init_utf16', 'il2cpp_shutdown', 'il2cpp_set_config_dir',
    'il2cpp_set_data_dir', 'il2cpp_set_temp_dir', 'il2cpp_set_commandline_arguments',
    'il2cpp_get_corlib', 'il2cpp_add_internal_call', 'il2cpp_resolve_icall',
    'il2cpp_alloc', 'il2cpp_free', 'il2cpp_array_class_get', 'il2cpp_array_length',
    'il2cpp_assembly_get_image', 'il2cpp_class_from_il2cpp_type',
    'il2cpp_class_from_name', 'il2cpp_class_from_system_type', 'il2cpp_class_get_element_class',
    'il2cpp_class_get_events', 'il2cpp_class_get_fields', 'il2cpp_class_get_nested_types',
    'il2cpp_class_get_interfaces', 'il2cpp_class_get_properties', 'il2cpp_class_get_property_from_name',
    'il2cpp_class_get_field_from_name', 'il2cpp_class_get_methods', 'il2cpp_class_get_method_from_name',
    'il2cpp_class_get_name', 'il2cpp_class_get_namespace', 'il2cpp_class_get_parent',
    'il2cpp_class_get_declaring_type', 'il2cpp_class_instance_size', 'il2cpp_class_num_fields',
    'il2cpp_class_is_valuetype', 'il2cpp_class_value_size', 'il2cpp_class_is_blittable',
    'il2cpp_class_get_flags', 'il2cpp_class_is_abstract', 'il2cpp_class_is_interface',
    'il2cpp_class_is_assignable_from', 'il2cpp_class_is_subclass_of', 'il2cpp_class_has_parent',
    'il2cpp_class_is_enum', 'il2cpp_class_get_image', 'il2cpp_class_get_assemblyname',
    'il2cpp_class_get_rank', 'il2cpp_class_get_bitmap_size', 'il2cpp_class_get_bitmap',
    'il2cpp_domain_get', 'il2cpp_domain_assembly_open', 'il2cpp_domain_get_assemblies',
    'il2cpp_image_get_assembly', 'il2cpp_image_get_name', 'il2cpp_image_get_filename',
    'il2cpp_image_get_entry_point', 'il2cpp_image_get_class_count', 'il2cpp_image_get_class',
    'il2cpp_method_get_return_type', 'il2cpp_method_get_declaring_type', 'il2cpp_method_get_name',
    'il2cpp_method_get_param_name', 'il2cpp_method_get_flags', 'il2cpp_method_get_token',
    'il2cpp_method_get_param_count', 'il2cpp_method_get_param', 'il2cpp_method_get_class',
    'il2cpp_type_get_object', 'il2cpp_type_get_type', 'il2cpp_type_get_class_or_element_class',
    'il2cpp_type_get_name', 'il2cpp_type_get_class_or_element_class'
  ];

  // IL2CPP type-enum -> readable primitive name (subset). See Il2CppTypeEnum.
  var TYPE_ENUM = {
    1: 'Void', 2: 'Boolean', 3: 'Char', 4: 'SByte', 5: 'Byte', 6: 'Int16', 7: 'UInt16',
    8: 'Int32', 9: 'UInt32', 10: 'Int64', 11: 'UInt64', 12: 'Single', 13: 'Double',
    14: 'String', 15: 'Ptr', 17: 'ValueType', 18: 'Class', 20: 'Array', 22: 'TypedByRef',
    24: 'IntPtr', 25: 'UIntPtr', 28: 'Object', 29: 'SzArray', 30: 'Var', 31: 'MVar'
  };

  function build(resolved) {
    // resolved: {name -> NativePointer}. Returns {name -> NativeFunction}.
    var fns = {};
    Object.keys(SIG).forEach(function (n) {
      if (resolved[n] && !resolved[n].isNull()) {
        try { fns[n] = new NativeFunction(resolved[n], SIG[n][0], SIG[n][1]); } catch (e) {}
      }
    });
    return fns;
  }

  KS.il2cppDefs = {
    SIG: SIG,
    CANONICAL_ORDER_HINT: CANONICAL_ORDER_HINT,
    TYPE_ENUM: TYPE_ENUM,
    build: build,
    // Non-allocating best-effort return/param type name via class accessors.
    typeName: function (fns, typePtr) {
      try {
        if (!typePtr || typePtr.isNull()) return null;
        var e = fns.il2cpp_type_get_type ? fns.il2cpp_type_get_type(typePtr) : null;
        var prim = (e !== null && TYPE_ENUM[e]) ? TYPE_ENUM[e] : null;
        if (prim && ['Void', 'Boolean', 'Char', 'SByte', 'Byte', 'Int16', 'UInt16', 'Int32', 'UInt32', 'Int64', 'UInt64', 'Single', 'Double', 'String', 'Object', 'IntPtr', 'UIntPtr'].indexOf(prim) !== -1)
          return prim;
        if (fns.il2cpp_type_get_class_or_element_class && fns.il2cpp_class_get_name) {
          var k = fns.il2cpp_type_get_class_or_element_class(typePtr);
          if (k && !k.isNull()) {
            var nm = U.readCStr(fns.il2cpp_class_get_name(k), 200);
            return (prim && prim.indexOf('Array') !== -1) ? (nm + '[]') : nm;
          }
        }
        return prim || null;
      } catch (e) { return null; }
    },
    // MethodInfo.methodPointer is field +0 in v24..v29 -> RVA of native code.
    methodRva: function (methodInfoPtr, il2cppBase) {
      try {
        if (!methodInfoPtr || methodInfoPtr.isNull()) return null;
        var mp = methodInfoPtr.readPointer();
        if (mp.isNull()) return null;
        var m = Process.findModuleByAddress(mp);
        if (m) return { module: m.name, rva: '0x' + mp.sub(m.base).toString(16), abs: mp.toString() };
        if (il2cppBase) return { module: 'libil2cpp.so?', rva: '0x' + mp.sub(il2cppBase).toString(16), abs: mp.toString() };
        return { abs: mp.toString() };
      } catch (e) { return null; }
    }
  };
})();
