use rusqlite::{Connection,Result,ffi,vtab::{Context,Filters,IndexInfo,Module,VTab,VTabConnection,VTabCursor}};
use std::{borrow::Cow,ffi::{CStr,CString,c_int}};

#[repr(C)] struct Table {base:ffi::sqlite3_vtab}
unsafe impl<'a> VTab<'a> for Table {
 type Aux=(); type Cursor=Cursor;
 fn connect(_: &mut VTabConnection,_:Option<&()>,_:&[u8],_:&[u8],_:&[u8],_:&[&[u8]])->Result<(Cow<'static,CStr>,Self)> {
  Ok((Cow::Owned(CString::new("CREATE TABLE x(v NUMERIC)").unwrap()),Self{base:ffi::sqlite3_vtab::default()}))
 }
 fn best_index(&self,_:&mut IndexInfo)->Result<bool>{Ok(true)}
 fn open(&mut self)->Result<Cursor>{Ok(Cursor{base:ffi::sqlite3_vtab_cursor::default(),index:0})}
}
#[repr(C)] struct Cursor{base:ffi::sqlite3_vtab_cursor,index:usize}
unsafe impl VTabCursor for Cursor{
 fn filter(&mut self,_:c_int,_:Option<&str>,_:&Filters<'_>)->Result<()>{self.index=0;Ok(())}
 fn next(&mut self)->Result<()>{self.index+=1;Ok(())}
 fn eof(&self)->bool{self.index>=2}
 fn column(&self,ctx:&mut Context,_:c_int)->Result<()>{ctx.set_result(&["01","1"][self.index])}
 fn rowid(&self)->Result<i64>{Ok(self.index as i64)}
}
fn main()->Result<()>{
 const MOD:Module<Table>=Module::eponymous_only_module();
 let db=Connection::open_in_memory()?;
 db.create_module(c"test_numeric",&MOD,Some(()))?;
 db.execute_batch("CREATE TABLE ordinary(v NUMERIC); INSERT INTO ordinary VALUES('01'),('1');")?;
 let mut tables=serde_json::Map::new();
 for (label,sql) in [("virtual","SELECT quote(v),typeof(v),v='1',v=1 FROM test_numeric ORDER BY rowid"),("ordinary","SELECT quote(v),typeof(v),v='1',v=1 FROM ordinary ORDER BY rowid")]{
  let mut statement=db.prepare(sql)?;
  let rows=statement.query_map([],|r|Ok(serde_json::json!([r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?])))?.collect::<Result<Vec<_>>>()?;
  tables.insert(label.into(),serde_json::json!({"sql":sql,"rows":rows}));
 }
 println!("{}",serde_json::json!({"sqlite_version":rusqlite::version(),"tables":tables}));
 Ok(())
}
