use codegen::cfg::HashTy;
use link::link;
use parser::pt;
use sema::ast;
use std::collections::HashMap;
use std::str;

use inkwell::attributes::{Attribute, AttributeLoc};
use inkwell::context::Context;
use inkwell::module::Linkage;
use inkwell::types::BasicTypeEnum;
use inkwell::types::{BasicType, IntType};
use inkwell::values::{BasicValueEnum, FunctionValue, IntValue, PointerValue};
use inkwell::AddressSpace;
use inkwell::IntPredicate;
use inkwell::OptimizationLevel;
use tiny_keccak::{Hasher, Keccak};

use super::ethabiencoder;
use super::{Contract, TargetRuntime, Variable};
use crate::Target;

pub struct LachainTarget {
    abi: ethabiencoder::EthAbiEncoder,
}

impl LachainTarget {
    pub fn build<'a>(
        context: &'a Context,
        contract: &'a ast::Contract,
        ns: &'a ast::Namespace,
        filename: &'a str,
        opt: OptimizationLevel,
    ) -> Contract<'a> {
        // first emit runtime code
        let mut runtime_code = Contract::new(context, contract, ns,filename, opt,None);
        let mut b = LachainTarget {
            abi: ethabiencoder::EthAbiEncoder {},
        };

        // externals
        b.declare_externals(&mut runtime_code);

        // FIXME: this also emits the constructors. We can either rely on lto linking
        // to optimize them away or do not emit them.
        runtime_code.emit_functions(&mut b);

        b.emit_function_dispatch(&runtime_code);

        let runtime_obj = runtime_code.wasm(true).unwrap();
        let runtime_bs = runtime_code.wasm(true).unwrap();//link(&runtime_obj, &Target::Lachain);

        // Now we have the runtime code, create the deployer
        let mut deploy_code =
            Contract::new(context, contract, ns,filename, opt,Some(Box::new(runtime_code)));
        let mut b = LachainTarget {
            abi: ethabiencoder::EthAbiEncoder {},
        };

        // externals
        b.declare_externals(&mut deploy_code);

        // FIXME: this emits the constructors, as well as the functions. In Ethereum Solidity,
        // no functions can be called from the constructor. We should either disallow this too
        // and not emit functions, or use lto linking to optimize any unused functions away.
        deploy_code.emit_functions(&mut b);

        //b.emit_constructor_dispatch(&mut deploy_code, &runtime_bs);

        deploy_code
    }

    fn main_prelude<'a>(
        &self,
        contract: &'a Contract,
        function: FunctionValue,
    ) -> (PointerValue<'a>, IntValue<'a>) {
        let entry = contract.context.append_basic_block(function, "entry");

        contract.builder.position_at_end(entry);

        // init our heap
        contract.builder.build_call(
            contract.module.get_function("__init_heap").unwrap(),
            &[],
            "",
        );

        // copy arguments from scratch buffer
        let args_length = contract
            .builder
            .build_call(
                contract.module.get_function("get_call_size").unwrap(),
                &[],
                "calldatasize",
            )
            .try_as_basic_value()
            .left()
            .unwrap();

        let args = contract
            .builder
            .build_call(
                contract.module.get_function("__malloc").unwrap(),
                &[args_length],
                "",
            )
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_pointer_value();

        contract.builder.build_call(
            contract.module.get_function("copy_call_value").unwrap(),
            &[
                contract.context.i32_type().const_zero().into(),
                args_length,
                args.into(),
            ],
            "",
        );

        let args = contract.builder.build_pointer_cast(
            args,
            contract.context.i32_type().ptr_type(AddressSpace::Generic),
            "",
        );

        (args, args_length.into_int_value())
    }

    fn declare_externals(&self, contract: &mut Contract) {
        let ret = contract.context.void_type();
        let args: Vec<BasicTypeEnum> = vec![
            contract
                .context
                .i8_type()
                .ptr_type(AddressSpace::Generic)
                .into(),
            contract
                .context
                .i8_type()
                .ptr_type(AddressSpace::Generic)
                .into(),
        ];

        let ftype = ret.fn_type(&args, false);

        contract
            .module
            .add_function("save_storage", ftype, Some(Linkage::External));
        contract
            .module
            .add_function("load_storage", ftype, Some(Linkage::External));

        contract.module.add_function(
            "get_call_size",
            contract.context.i32_type().fn_type(&[], false),
            Some(Linkage::External),
        );

        contract.module.add_function(
            "copy_call_value",
            contract.context.void_type().fn_type(
                &[
                    contract.context.i32_type().into(), // fromOffset
                    contract.context.i32_type().into(), // toOffset (fromOffset+length)
                    contract
                        .context
                        .i8_type()
                        .ptr_type(AddressSpace::Generic)
                        .into(), // toMemoryPtr
                ],
                false,
            ),
            Some(Linkage::External),
        );

        let noreturn = contract
            .context
            .create_enum_attribute(Attribute::get_named_enum_kind_id("noreturn"), 0);

        // mark as noreturn
        contract
            .module
            .add_function(
                "exit_contract",
                contract.context.void_type().fn_type(
                    &[
                        contract
                            .context
                            .i8_type()
                            .ptr_type(AddressSpace::Generic)
                            .into(), // data_ptr
                        contract.context.i32_type().into(), // data_len
                    ],
                    false,
                ),
                Some(Linkage::External),
            )
            .add_attribute(AttributeLoc::Function, noreturn);

        contract
            .module
            .add_function(
                "set_return",
                contract.context.void_type().fn_type(
                    &[
                        contract
                            .context
                            .i8_type()
                            .ptr_type(AddressSpace::Generic)
                            .into(), // data_ptr
                        contract.context.i32_type().into(), // data_len
                    ],
                    false,
                ),
                Some(Linkage::External),
            )
            .add_attribute(AttributeLoc::Function, noreturn);

        // mark as noreturn
        contract
            .module
            .add_function(
                "system_halt",
                contract.context.void_type().fn_type(
                    &[
                        contract.context.i32_type().into(), // halt code
                    ],
                    false,
                ),
                Some(Linkage::External),
            )
            .add_attribute(AttributeLoc::Function, noreturn);
    }

    /*fn emit_constructor_dispatch(&self, contract: &mut Contract, runtime: &[u8]) {
        let initializer = contract.emit_initializer(self);

        // create start function
        let ret = contract.context.void_type();
        let ftype = ret.fn_type(&[], false);
        let function = contract.module.add_function("main", ftype, None);

        // FIXME: If there is no constructor, do not copy the calldata (but check calldatasize == 0)
        let (argsdata, length) = self.main_prelude(contract, function);

        // init our storage vars
        contract.builder.build_call(initializer, &[], "");

        if let Some(con) = contract.ns.constructors.get(0) {
            let mut args = Vec::new();

            // insert abi decode
            self.abi
                .decode(contract, function, &mut args, argsdata, length, con);

            contract
                .builder
                .build_call(contract.constructors[0], &args, "");
        }

        // the deploy code should return the runtime wasm code
        let runtime_code = contract.emit_global_string("runtime_code", runtime, true);

        let runtime_ptr = contract.builder.build_pointer_cast(
            contract.globals[runtime_code].as_pointer_value(),
            contract.context.i8_type().ptr_type(AddressSpace::Generic),
            "runtime_code",
        );

        contract.builder.build_call(
            contract.module.get_function("exit_contract").unwrap(),
            &[
                runtime_ptr.into(),
                contract
                    .context
                    .i32_type()
                    .const_int(runtime.len() as u64, false)
                    .into(),
            ],
            "",
        );

        // since finish is marked noreturn, this should be optimized away
        // however it is needed to create valid LLVM IR
        contract.builder.build_unreachable();
    }*/

    fn emit_function_dispatch(&mut self, contract: &Contract) {
        // create start function
        let ret = contract.context.void_type();
        let ftype = ret.fn_type(&[], false);
        let function = contract.module.add_function("main", ftype, None);

        let (argsdata, argslen) = self.main_prelude(contract, function);

        //let fallback_block = contract.context.append_basic_block(function, "fallback");

        /*
        contract.emit_function_dispatch(
            pt::FunctionTy::Function,
            argsdata,
            argslen,
            function,
            None,
            self,
            |func| !contract.function_abort_value_transfers && func.nonpayable,
        );*/

        // emit fallback code
        //contract.builder.position_at_end(fallback_block);

        /*
        match contract.ns.fallback_function() {
            Some(f) => {
                contract.builder.build_call(contract.functions[f], &[], "");

                contract.builder.build_return(None);
            }
            None => {
                contract.builder.build_unreachable();
            }
        }*/
    }
}

impl TargetRuntime for LachainTarget {
    fn clear_storage<'a>(
        &self,
        contract: &'a Contract,
        _function: FunctionValue,
        slot: PointerValue<'a>,
    ) {
        let value = contract
            .builder
            .build_alloca(contract.context.custom_width_int_type(256), "value");

        let value8 = contract.builder.build_pointer_cast(
            value,
            contract.context.i8_type().ptr_type(AddressSpace::Generic),
            "value8",
        );

        contract.builder.build_call(
            contract.module.get_function("__bzero8").unwrap(),
            &[
                value8.into(),
                contract.context.i32_type().const_int(4, false).into(),
            ],
            "",
        );

        contract.builder.build_call(
            contract.module.get_function("save_storage").unwrap(),
            &[
                contract
                    .builder
                    .build_pointer_cast(
                        slot,
                        contract.context.i8_type().ptr_type(AddressSpace::Generic),
                        "",
                    )
                    .into(),
                value8.into(),
            ],
            "",
        );
    }

    fn set_storage<'a>(
        &self,
        contract: &'a Contract,
        _function: FunctionValue,
        slot: PointerValue<'a>,
        dest: PointerValue<'a>,
    ) {
        let value = contract
            .builder
            .build_alloca(contract.context.custom_width_int_type(256), "value");

        let value8 = contract.builder.build_pointer_cast(
            value,
            contract.context.i8_type().ptr_type(AddressSpace::Generic),
            "value8",
        );

        contract.builder.build_call(
            contract.module.get_function("__bzero8").unwrap(),
            &[
                value8.into(),
                contract.context.i32_type().const_int(4, false).into(),
            ],
            "",
        );

        let val = contract.builder.build_load(dest, "value");

        contract.builder.build_store(
            contract
                .builder
                .build_pointer_cast(value, dest.get_type(), ""),
            val,
        );

        contract.builder.build_call(
            contract.module.get_function("save_storage").unwrap(),
            &[
                contract
                    .builder
                    .build_pointer_cast(
                        slot,
                        contract.context.i8_type().ptr_type(AddressSpace::Generic),
                        "",
                    )
                    .into(),
                value8.into(),
            ],
            "",
        );
    }

    fn set_storage_string<'a>(
        &self,
        _contract: &'a Contract,
        _function: FunctionValue,
        _slot: PointerValue<'a>,
        _dest: PointerValue<'a>,
    ) {
        unimplemented!();
    }

    fn get_storage_string<'a>(
        &self,
        _contract: &Contract<'a>,
        _function: FunctionValue,
        _slot: PointerValue<'a>,
    ) -> PointerValue<'a> {
        unimplemented!();
    }
    fn get_storage_bytes_subscript<'a>(
        &self,
        _contract: &Contract<'a>,
        _function: FunctionValue,
        _slot: PointerValue<'a>,
        _index: IntValue<'a>,
    ) -> IntValue<'a> {
        unimplemented!();
    }
    fn set_storage_bytes_subscript<'a>(
        &self,
        _contract: &Contract<'a>,
        _function: FunctionValue,
        _slot: PointerValue<'a>,
        _index: IntValue<'a>,
        _val: IntValue<'a>,
    ) {
        unimplemented!();
    }
    fn storage_bytes_push<'a>(
        &self,
        _contract: &Contract<'a>,
        _function: FunctionValue,
        _slot: PointerValue<'a>,
        _val: IntValue<'a>,
    ) {
        unimplemented!();
    }
    fn storage_bytes_pop<'a>(
        &self,
        _contract: &Contract<'a>,
        _function: FunctionValue,
        _slot: PointerValue<'a>,
    ) -> IntValue<'a> {
        unimplemented!();
    }
    fn storage_string_length<'a>(
        &self,
        _contract: &Contract<'a>,
        _function: FunctionValue,
        _slot: PointerValue<'a>,
    ) -> IntValue<'a> {
        unimplemented!();
    }

    fn get_storage_int<'a>(
        &self,
        contract: &Contract<'a>,
        function: FunctionValue,
        slot: PointerValue,
        ty: IntType<'a>,
    ) -> IntValue<'a> {
        let address = contract
            .builder
            .build_call(
                contract.module.get_function("alloc").unwrap(),
                &[contract.context.i32_type().const_int(64, false).into()],
                "address",
            )
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_pointer_value();

        // convert slot to address
        contract.builder.build_call(
            contract.module.get_function("__u256ptohex").unwrap(),
            &[
                contract
                    .builder
                    .build_pointer_cast(
                        slot,
                        contract.context.i8_type().ptr_type(AddressSpace::Generic),
                        "slot",
                    )
                    .into(),
                address.into(),
            ],
            "address_from_slot",
        );

        // create collection for set_state
        contract.builder.build_call(
            contract.module.get_function("create_collection").unwrap(),
            &[address.into()],
            "",
        );
        let res = contract
            .builder
            .build_call(
                contract.module.get_function("get_state").unwrap(),
                &[address.into()],
                "",
            )
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_pointer_value();

        let state_size = contract
            .builder
            .build_call(
                contract.module.get_function("get_ptr_len").unwrap(),
                &[res.into()],
                "",
            )
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        let data_size = ty.size_of();

        let exists = contract.builder.build_int_compare(
            IntPredicate::EQ,
            state_size,
            data_size,
            "storage_exists",
        );

        let entry = contract.builder.get_insert_block().unwrap();

        let retrieve_block = contract.context.append_basic_block(function, "in_storage");
        let done_storage = contract
            .context
            .append_basic_block(function, "done_storage");

        contract
            .builder
            .build_conditional_branch(exists, retrieve_block, done_storage);

        contract.builder.position_at_end(retrieve_block);

        let loaded_int = contract.builder.build_load(
            contract
                .builder
                .build_pointer_cast(res, ty.ptr_type(AddressSpace::Generic), ""),
            "loaded_int",
        );

        contract.builder.build_unconditional_branch(done_storage);

        let res = contract.builder.build_phi(ty, "storage_res");

        res.add_incoming(&[(&loaded_int, retrieve_block), (&ty.const_zero(), entry)]);

        res.as_basic_value().into_int_value()
    }

    /// sabre has no keccak256 host function, so call our implementation
    fn keccak256_hash(
        &self,
        contract: &Contract,
        src: PointerValue,
        length: IntValue,
        dest: PointerValue,
    ) {
        contract.builder.build_call(
            contract.module.get_function("sha3").unwrap(),
            &[
                contract
                    .builder
                    .build_pointer_cast(
                        src,
                        contract.context.i8_type().ptr_type(AddressSpace::Generic),
                        "src",
                    )
                    .into(),
                length.into(),
                contract
                    .builder
                    .build_pointer_cast(
                        dest,
                        contract.context.i8_type().ptr_type(AddressSpace::Generic),
                        "dest",
                    )
                    .into(),
                contract.context.i32_type().const_int(32, false).into(),
            ],
            "",
        );
    }

    fn return_empty_abi(&self, contract: &Contract) {
        contract.builder.build_call(
            contract.module.get_function("exit_contract").unwrap(),
            &[
                contract
                    .context
                    .i8_type()
                    .ptr_type(AddressSpace::Generic)
                    .const_zero()
                    .into(),
                contract.context.i32_type().const_zero().into(),
            ],
            "",
        );

        contract.builder.build_return(None);
    }

    fn return_abi<'b>(&self, contract: &'b Contract, data: PointerValue<'b>, length: IntValue) {
        contract.builder.build_call(
            contract.module.get_function("exit_contract").unwrap(),
            &[data.into(), length.into()],
            "",
        );

        contract.builder.build_return(None);
    }

    fn assert_failure<'b>(&self, contract: &'b Contract, data: PointerValue, length: IntValue) {
        contract.builder.build_call(
            contract.module.get_function("set_return").unwrap(),
            &[
                contract
                    .context
                    .i8_type()
                    .ptr_type(AddressSpace::Generic)
                    .const_zero()
                    .into(),
                contract.context.i32_type().const_zero().into(),
            ],
            "",
        );

        contract.builder.build_call(
            contract.module.get_function("system_halt").unwrap(),
            &[
                contract.context.i32_type().const_int(7, false).into(),
            ],
            "",
        );

        // since revert is marked noreturn, this should be optimized away
        // however it is needed to create valid LLVM IR
        contract.builder.build_unreachable();
    }

    /// ABI encode into a vector for abi.encode* style builtin functions
    fn abi_encode_to_vector<'b>(
        &self,
        _contract: &Contract<'b>,
        _selector: Option<IntValue<'b>>,
        _function: FunctionValue,
        _packed: bool,
        _args: &[BasicValueEnum<'b>],
        _spec: &[ast::Type],
    ) -> PointerValue<'b> {
        unimplemented!();
    }

    fn abi_encode<'b>(
        &self,
        contract: &Contract<'b>,
        selector: Option<u32>,
        load: bool,
        function: FunctionValue,
        args: &[BasicValueEnum<'b>],
        spec: &[ast::Parameter],
    ) -> (PointerValue<'b>, IntValue<'b>) {
        let mut offset = contract.context.i32_type().const_int(
            spec.iter()
                .map(|arg| self.abi.encoded_fixed_length(&arg.ty, contract.ns))
                .sum(),
            false,
        );

        let mut length = offset;

        let encoded_data = contract
            .builder
            .build_call(
                contract.module.get_function("__malloc").unwrap(),
                &[length.into()],
                "",
            )
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_pointer_value();

        // malloc returns u8*
        let mut data = encoded_data;

        for (i, arg) in spec.iter().enumerate() {
            let val = if arg.ty.is_reference_type() {
                contract
                    .builder
                    .build_load(args[i].into_pointer_value(), "")
            } else {
                args[i]
            };

            let mut dynamic = unsafe { contract.builder.build_gep(data, &[offset], "") };

            self.abi
                .encode_ty(
                    contract,
                    load,
                    function,
                    &arg.ty,
                    args[i],
                    &mut data,
                    &mut offset,
                    &mut dynamic,
                );
        }

        (encoded_data, length)
    }

    fn abi_decode<'b>(
        &self,
        contract: &Contract<'b>,
        function: FunctionValue,
        args: &mut Vec<BasicValueEnum<'b>>,
        data: PointerValue<'b>,
        length: IntValue<'b>,
        spec: &[ast::Parameter],
    ) {
        self.abi
            .decode(contract, function, args, data, length, spec);
    }

    fn print(&self, contract: &Contract, string_ptr: PointerValue, string_len: IntValue) {
        contract.builder.build_call(
            contract.module.get_function("log_buffer").unwrap(),
            &[
                contract.context.i32_type().const_int(2, false).into(),
                string_ptr.into(),
                string_len.into(),
            ],
            "",
        );
    }

    fn create_contract<'b>(
        &mut self,
        contract: &Contract<'b>,
        function: FunctionValue,
        success: Option<&mut BasicValueEnum<'b>>,
        contract_no: usize,
        constructor_no: Option<usize>,
        address: PointerValue<'b>,
        args: &[BasicValueEnum<'b>],
        _gas: IntValue<'b>,
        value: Option<IntValue<'b>>,
        _salt: Option<IntValue<'b>>,
    ) {
        let resolver_contract = &contract.ns.contracts[contract_no];

        let target_contract = Contract::build(
            contract.context,
            &resolver_contract,
            contract.ns,
            "",
            contract.opt,
        );

        // wasm
        let wasm = target_contract.wasm(true).expect("compile should succeeed");

        let code = contract.emit_global_string(
            &format!("contract_{}_code", resolver_contract.name),
            &wasm,
            true,
        );

        let params = match constructor_no {
            Some(function_no) => resolver_contract.functions[function_no].params.as_slice(),
            None => &[],
        };

        // input
        let (input, input_len) = self.abi_encode(
            contract,
            None,
            false,
            function,
            args,
            params,
        );

        // value is a u128
        let value_ptr = contract
            .builder
            .build_alloca(contract.value_type(), "balance");

        contract.builder.build_store(
            value_ptr,
            match value {
                Some(v) => v,
                None => contract.value_type().const_zero(),
            },
        );

        // call create
        let ret = contract
            .builder
            .build_call(
                contract.module.get_function("create").unwrap(),
                &[
                    contract
                        .builder
                        .build_pointer_cast(
                            value_ptr,
                            contract.context.i8_type().ptr_type(AddressSpace::Generic),
                            "value_transfer",
                        )
                        .into(),
                    input.into(),
                    input_len.into(),
                    address.into(),
                ],
                "",
            )
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        let is_success = contract.builder.build_int_compare(
            IntPredicate::EQ,
            ret,
            contract.context.i32_type().const_zero(),
            "success",
        );

        if let Some(success) = success {
            *success = is_success.into();
        } else {
            let success_block = contract.context.append_basic_block(function, "success");
            let bail_block = contract.context.append_basic_block(function, "bail");
            contract
                .builder
                .build_conditional_branch(is_success, success_block, bail_block);

            contract.builder.position_at_end(bail_block);

            self.assert_failure(
                contract,
                contract
                    .context
                    .i8_type()
                    .ptr_type(AddressSpace::Generic)
                    .const_null(),
                contract.context.i32_type().const_zero(),
            );

            contract.builder.position_at_end(success_block);
        }
    }

    fn external_call<'b>(
        &self,
        contract: &Contract<'b>,
        payload: PointerValue<'b>,
        payload_len: IntValue<'b>,
        address: PointerValue<'b>,
        gas: IntValue<'b>,
        value: IntValue<'b>,
        callty: ast::CallTy,
    ) -> IntValue<'b> {
        // value is a u128
        let value_ptr = contract
            .builder
            .build_alloca(contract.value_type(), "balance");
        contract.builder.build_store(value_ptr, value);

        // call create
        contract
            .builder
            .build_call(
                contract
                    .module
                    .get_function(match callty {
                        ast::CallTy::Regular => "call",
                        ast::CallTy::Static => "callStatic",
                        ast::CallTy::Delegate => "callDelegate",
                    })
                    .unwrap(),
                &[
                    gas.into(),
                    address.into(),
                    contract
                        .builder
                        .build_pointer_cast(
                            value_ptr,
                            contract.context.i8_type().ptr_type(AddressSpace::Generic),
                            "value_transfer",
                        )
                        .into(),
                    payload.into(),
                    payload_len.into(),
                ],
                "",
            )
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value()
    }

    fn return_data<'b>(&self, contract: &Contract<'b>) -> PointerValue<'b> {
        let length = contract
            .builder
            .build_call(
                contract.module.get_function("getReturnDataSize").unwrap(),
                &[],
                "returndatasize",
            )
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        let malloc_length = contract.builder.build_int_add(
            length,
            contract
                .module
                .get_struct_type("struct.vector")
                .unwrap()
                .size_of()
                .unwrap()
                .const_cast(contract.context.i32_type(), false),
            "size",
        );

        let p = contract
            .builder
            .build_call(
                contract.module.get_function("__malloc").unwrap(),
                &[malloc_length.into()],
                "",
            )
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_pointer_value();

        let v = contract.builder.build_pointer_cast(
            p,
            contract
                .module
                .get_struct_type("struct.vector")
                .unwrap()
                .ptr_type(AddressSpace::Generic),
            "string",
        );

        let data_len = unsafe {
            contract.builder.build_gep(
                v,
                &[
                    contract.context.i32_type().const_zero(),
                    contract.context.i32_type().const_zero(),
                ],
                "data_len",
            )
        };

        contract.builder.build_store(data_len, length);

        let data_size = unsafe {
            contract.builder.build_gep(
                v,
                &[
                    contract.context.i32_type().const_zero(),
                    contract.context.i32_type().const_int(1, false),
                ],
                "data_size",
            )
        };

        contract.builder.build_store(data_size, length);

        let data = unsafe {
            contract.builder.build_gep(
                v,
                &[
                    contract.context.i32_type().const_zero(),
                    contract.context.i32_type().const_int(2, false),
                ],
                "data",
            )
        };

        contract.builder.build_call(
            contract.module.get_function("returnDataCopy").unwrap(),
            &[
                contract
                    .builder
                    .build_pointer_cast(
                        data,
                        contract.context.i8_type().ptr_type(AddressSpace::Generic),
                        "",
                    )
                    .into(),
                contract.context.i32_type().const_zero().into(),
                length.into(),
            ],
            "",
        );

        v
    }

    /// builtin expressions
    fn builtin<'b>(
        &self,
        _contract: &Contract<'b>,
        _expr: &ast::Expression,
        _vartab: &HashMap<usize, Variable<'b>>,
        _function: FunctionValue<'b>,
        _runtime: &dyn TargetRuntime,
    ) -> BasicValueEnum<'b> {
        unimplemented!();
    }

    /// ewasm value is always 128 bits
    fn value_transferred<'b>(&self, contract: &Contract<'b>) -> IntValue<'b> {
        let value = contract
            .builder
            .build_alloca(contract.value_type(), "value_transferred");

        contract.builder.build_call(
            contract.module.get_function("getCallValue").unwrap(),
            &[contract
                .builder
                .build_pointer_cast(
                    value,
                    contract.context.i8_type().ptr_type(AddressSpace::Generic),
                    "",
                )
                .into()],
            "value_transferred",
        );

        contract
            .builder
            .build_load(value, "value_transferred")
            .into_int_value()
    }

    /// ewasm address is always 160 bits
    fn get_address<'b>(&self, contract: &Contract<'b>) -> IntValue<'b> {
        let value = contract
            .builder
            .build_alloca(contract.address_type(), "self_address");

        contract.builder.build_call(
            contract.module.get_function("getAddress").unwrap(),
            &[contract
                .builder
                .build_pointer_cast(
                    value,
                    contract.context.i8_type().ptr_type(AddressSpace::Generic),
                    "",
                )
                .into()],
            "self_address",
        );

        contract
            .builder
            .build_load(value, "self_address")
            .into_int_value()
    }

    /// ewasm address is always 160 bits
    fn balance<'b>(&self, contract: &Contract<'b>, addr: IntValue<'b>) -> IntValue<'b> {
        let address = contract
            .builder
            .build_alloca(contract.address_type(), "address");

        contract.builder.build_store(address, addr);

        let balance = contract
            .builder
            .build_alloca(contract.value_type(), "balance");

        contract.builder.build_call(
            contract.module.get_function("getExternalBalance").unwrap(),
            &[
                contract
                    .builder
                    .build_pointer_cast(
                        address,
                        contract.context.i8_type().ptr_type(AddressSpace::Generic),
                        "",
                    )
                    .into(),
                contract
                    .builder
                    .build_pointer_cast(
                        balance,
                        contract.context.i8_type().ptr_type(AddressSpace::Generic),
                        "",
                    )
                    .into(),
            ],
            "balance",
        );

        contract
            .builder
            .build_load(balance, "balance")
            .into_int_value()
    }

    /// Terminate execution, destroy contract and send remaining funds to addr
    fn selfdestruct<'b>(&self, contract: &Contract<'b>, addr: IntValue<'b>) {
        let address = contract
            .builder
            .build_alloca(contract.address_type(), "address");

        contract.builder.build_store(address, addr);

        contract.builder.build_call(
            contract.module.get_function("selfDestruct").unwrap(),
            &[contract
                .builder
                .build_pointer_cast(
                    address,
                    contract.context.i8_type().ptr_type(AddressSpace::Generic),
                    "",
                )
                .into()],
            "terminated",
        );
    }

    /// Crypto Hash
    fn hash<'b>(
        &self,
        contract: &Contract<'b>,
        hash: HashTy,
        input: PointerValue<'b>,
        input_len: IntValue<'b>,
    ) -> IntValue<'b> {
        let (precompile, hashlen) = match hash {
            HashTy::Keccak256 => (0, 32),
            HashTy::Ripemd160 => (3, 20),
            HashTy::Sha256 => (2, 32),
            _ => unreachable!(),
        };

        let res = contract.builder.build_array_alloca(
            contract.context.i8_type(),
            contract.context.i32_type().const_int(hashlen, false),
            "res",
        );

        if hash == HashTy::Keccak256 {
            contract.builder.build_call(
                contract.module.get_function("sha3").unwrap(),
                &[
                    input.into(),
                    input_len.into(),
                    res.into(),
                    contract.context.i32_type().const_int(hashlen, false).into(),
                ],
                "",
            );
        } else {
            let balance = contract
                .builder
                .build_alloca(contract.value_type(), "balance");

            contract
                .builder
                .build_store(balance, contract.value_type().const_zero());

            let address = contract
                .builder
                .build_alloca(contract.address_type(), "address");

            contract.builder.build_store(
                address,
                contract.address_type().const_int(precompile, false),
            );

            contract.builder.build_call(
                contract.module.get_function("call").unwrap(),
                &[
                    contract.context.i64_type().const_zero().into(),
                    contract
                        .builder
                        .build_pointer_cast(
                            address,
                            contract.context.i8_type().ptr_type(AddressSpace::Generic),
                            "address",
                        )
                        .into(),
                    contract
                        .builder
                        .build_pointer_cast(
                            balance,
                            contract.context.i8_type().ptr_type(AddressSpace::Generic),
                            "balance",
                        )
                        .into(),
                    input.into(),
                    input_len.into(),
                ],
                "",
            );

            // We're not checking return value or returnDataSize;
            // assuming precompiles always succeed

            contract.builder.build_call(
                contract.module.get_function("returnDataCopy").unwrap(),
                &[
                    res.into(),
                    contract.context.i32_type().const_zero().into(),
                    contract.context.i32_type().const_int(hashlen, false).into(),
                ],
                "",
            );
        }

        // bytes32 needs to reverse bytes
        let temp = contract
            .builder
            .build_alloca(contract.llvm_type(&ast::Type::Bytes(hashlen as u8)), "hash");

        contract.builder.build_call(
            contract.module.get_function("__beNtoleN").unwrap(),
            &[
                res.into(),
                contract
                    .builder
                    .build_pointer_cast(
                        temp,
                        contract.context.i8_type().ptr_type(AddressSpace::Generic),
                        "",
                    )
                    .into(),
                contract.context.i32_type().const_int(hashlen, false).into(),
            ],
            "",
        );

        contract.builder.build_load(temp, "hash").into_int_value()
    }

    /// Send event
    fn send_event<'b>(
        &self,
        contract: &Contract<'b>,
        event_no: usize,
        data: PointerValue<'b>,
        data_len: IntValue<'b>,
        topics: Vec<(PointerValue<'b>, IntValue<'b>)>,
    ) {
        let empty_topic = contract
            .context
            .i8_type()
            .ptr_type(AddressSpace::Generic)
            .const_null();

        let mut encoded_topics = [empty_topic; 4];

        let event = &contract.ns.events[event_no];

        let mut topic_count = 0;

        if !event.anonymous {
            let mut hasher = Keccak::v256();
            hasher.update(event.signature.as_bytes());
            let mut hash = [0u8; 32];
            hasher.finalize(&mut hash);

            encoded_topics[0] =
                contract.emit_global_string(&format!("event_{}_signature", event), &hash, true);

            topic_count += 1;
        }

        for (ptr, len) in topics.into_iter() {
            if let Some(32) = len.get_zero_extended_constant() {
                encoded_topics[topic_count] = ptr;
            } else {
                let dest = contract.builder.build_array_alloca(
                    contract.context.i8_type(),
                    contract.context.i32_type().const_int(32, false),
                    "hash",
                );

                self.keccak256_hash(contract, ptr, len, dest);

                encoded_topics[topic_count] = dest;
            }

            topic_count += 1;
        }

        contract.builder.build_call(
            contract.module.get_function("log").unwrap(),
            &[
                data.into(),
                data_len.into(),
                contract
                    .context
                    .i32_type()
                    .const_int(topic_count as u64, false)
                    .into(),
                encoded_topics[0].into(),
                encoded_topics[1].into(),
                encoded_topics[2].into(),
                encoded_topics[3].into(),
            ],
            "",
        );
    }

    // ewasm main cannot return any value
    fn return_u32<'b>(&self, contract: &'b Contract, _ret: IntValue<'b>) {
        self.assert_failure(
            contract,
            contract
                .context
                .i8_type()
                .ptr_type(AddressSpace::Generic)
                .const_null(),
            contract.context.i32_type().const_zero(),
        );
    }

}
