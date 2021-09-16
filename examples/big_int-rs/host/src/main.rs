// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
#![allow(unused)]
use optee_teec::{Context, Operation, ParamType, Session, Uuid};
use optee_teec::{ParamNone, ParamTmpRef, ParamValue};
use proto::{Command, UUID};

extern crate num_traits;
use std::convert::TryInto;
use std::iter::FromIterator;
use std::mem::replace;

// use num_bigint::ToPrimitive;
use num_traits::cast::ToPrimitive;
fn big_int(session: &mut Session) -> optee_teec::Result<()> {
    let number0 = [
        0x01u8, 0x23u8, 0x45u8, 0x67u8, 0x89u8, 0xabu8, 0xcdu8, 0xefu8,
    ];
    // FC3F2B49CBC0F62E862272Fu64
    // let number0 = b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
    // FC3F2B49CBC0F62E862272Fu64;
    println!("{:?}", &number0);
    let number1: u32 = 2;

    let p0 = ParamTmpRef::new_input(&number0);
    let p1 = ParamValue::new(number1, 0, ParamType::ValueInput);
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);

    session.invoke_command(Command::Compare as u32, &mut operation)?;
    session.invoke_command(Command::Convert as u32, &mut operation)?;
    session.invoke_command(Command::Add as u32, &mut operation)?;
    session.invoke_command(Command::Sub as u32, &mut operation)?;
    session.invoke_command(Command::Multiply as u32, &mut operation)?;
    session.invoke_command(Command::Divide as u32, &mut operation)?;
    session.invoke_command(Command::Module as u32, &mut operation)?;

    Ok(())
}

fn main() -> optee_teec::Result<()> {
    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;

    big_int(&mut session)?;

    println!("Success");
    Ok(())
}
