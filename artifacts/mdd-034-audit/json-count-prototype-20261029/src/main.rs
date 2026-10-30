use mdd_facts::{EntityKind,EntityRef};
use mdd_query::ir::{Bytes,Signed64,Value};
use mdd_types::DecimalU64;
use serde::{Serialize,Serializer,ser::{SerializeSeq,SerializeStruct,Error as SerError}};
use std::{alloc::{GlobalAlloc,Layout,System},fmt::{self,Write as _},io::{self,Write},sync::atomic::{AtomicBool,AtomicUsize,Ordering}};

struct TrackingAllocator;
static TRACK:AtomicBool=AtomicBool::new(false);
static LIVE:AtomicUsize=AtomicUsize::new(0);
static PEAK:AtomicUsize=AtomicUsize::new(0);
fn increase(n:usize){let value=LIVE.fetch_add(n,Ordering::SeqCst)+n;PEAK.fetch_max(value,Ordering::SeqCst);}
unsafe impl GlobalAlloc for TrackingAllocator{
 unsafe fn alloc(&self,l:Layout)->*mut u8{let p=unsafe{System.alloc(l)};if !p.is_null()&&TRACK.load(Ordering::SeqCst){increase(l.size())}p}
 unsafe fn dealloc(&self,p:*mut u8,l:Layout){if TRACK.load(Ordering::SeqCst){LIVE.fetch_sub(l.size(),Ordering::SeqCst);}unsafe{System.dealloc(p,l)}}
 unsafe fn realloc(&self,p:*mut u8,l:Layout,n:usize)->*mut u8{let q=unsafe{System.realloc(p,l,n)};if !q.is_null()&&TRACK.load(Ordering::SeqCst){if n>=l.size(){increase(n-l.size())}else{LIVE.fetch_sub(l.size()-n,Ordering::SeqCst);}}q}
}
#[global_allocator] static ALLOC:TrackingAllocator=TrackingAllocator;

#[derive(Debug,Clone,Copy,PartialEq,Eq)] enum Stop{Overflow,OutputLimit,Cancelled}
struct Counter{n:u64,cap:Option<u64>,cancel_after:Option<u64>,stop:Option<Stop>}
impl Write for Counter{
 fn write(&mut self,buf:&[u8])->io::Result<usize>{
  let amount=u64::try_from(buf.len()).map_err(|_|{self.stop=Some(Stop::Overflow);io::Error::other("counter overflow")})?;
  let next=self.n.checked_add(amount).ok_or_else(||{self.stop=Some(Stop::Overflow);io::Error::other("counter overflow")})?;
  if self.cancel_after.is_some_and(|n|next>n){self.stop=Some(Stop::Cancelled);return Err(io::Error::other("cancel sentinel"))}
  if self.cap.is_some_and(|n|next>n){self.stop=Some(Stop::OutputLimit);return Err(io::Error::other("quota sentinel"))}
  self.n=next;Ok(buf.len())
 }
 fn flush(&mut self)->io::Result<()>{Ok(())}
}
struct Base64Display<'a>(&'a[u8]);
impl fmt::Display for Base64Display<'_>{fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{
 let alphabet=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 for block in self.0.chunks(3){let bits=(u32::from(block[0])<<16)|(u32::from(*block.get(1).unwrap_or(&0))<<8)|u32::from(*block.get(2).unwrap_or(&0));
  for c in [alphabet[((bits>>18)&63)as usize],alphabet[((bits>>12)&63)as usize],if block.len()>1{alphabet[((bits>>6)&63)as usize]}else{b'='},if block.len()>2{alphabet[(bits&63)as usize]}else{b'='}]{f.write_char(char::from(c))?;}
 }Ok(())}}
struct EncodedBytes<'a>(&'a[u8]);
impl Serialize for EncodedBytes<'_>{fn serialize<S:Serializer>(&self,s:S)->Result<S::Ok,S::Error>{s.collect_str(&Base64Display(self.0))}}
struct WrappedValue<'a>(&'a Value);
impl Serialize for WrappedValue<'_>{fn serialize<S:Serializer>(&self,s:S)->Result<S::Ok,S::Error>{match self.0{
 Value::Bytes(bytes)=>{let mut st=s.serialize_struct("Value",2)?;st.serialize_field("type","bytes")?;st.serialize_field("value",&EncodedBytes(&bytes.0))?;st.end()},
 other=>other.serialize(s)}}}
struct WrappedRow<'a>(&'a[Value]);
impl Serialize for WrappedRow<'_>{fn serialize<S:Serializer>(&self,s:S)->Result<S::Ok,S::Error>{let mut seq=s.serialize_seq(Some(self.0.len()))?;for v in self.0{seq.serialize_element(&WrappedValue(v))?;}seq.end()}}
struct Broken;
impl Serialize for Broken{fn serialize<S:Serializer>(&self,_:S)->Result<S::Ok,S::Error>{Err(S::Error::custom("synthetic encoding failure"))}}
fn count<T:Serialize>(v:&T,cap:Option<u64>,initial:u64,cancel_after:Option<u64>)->(Result<(),serde_json::Error>,Counter){let mut w=Counter{n:initial,cap,cancel_after,stop:None};let r=serde_json::to_writer(&mut w,v);(r,w)}
fn measured<T:Serialize>(v:&T)->(usize,u64){LIVE.store(0,Ordering::SeqCst);PEAK.store(0,Ordering::SeqCst);TRACK.store(true,Ordering::SeqCst);let(r,w)=count(v,None,0,None);TRACK.store(false,Ordering::SeqCst);if r.is_err(){panic!("measurement unexpectedly failed")}(PEAK.load(Ordering::SeqCst),w.n)}
fn main(){
 let entity=EntityRef{snapshot_id:"snap\"\n雪".into(),dex_occurrence_id:"dex\\\0😀".into(),kind:EntityKind::MethodDefinition,local_index:42};
 let mut rows:Vec<Vec<Value>>=vec![vec![],vec![Value::Null,Value::Bool(false),Value::Bool(true),Value::I64(Signed64(i64::MIN)),Value::I64(Signed64(i64::MAX)),Value::U64(DecimalU64(u64::MAX)),Value::Utf16(vec![0,0xd800,0xdc00,0xffff]),Value::Entity(entity)]];
 for n in [0usize,1,2,3,4,5,4095,4096,4097,65536]{rows.push(vec![Value::Bytes(Bytes((0..n).map(|i|(i.wrapping_mul(37)%256)as u8).collect()))]);}
 let mut checked=Vec::new();for (i,row) in rows.iter().enumerate(){let old=serde_json::to_vec(row).unwrap();let new=serde_json::to_vec(&WrappedRow(row)).unwrap();let(r,w)=count(&WrappedRow(row),None,0,None);if r.is_err()||old!=new||w.n!=old.len()as u64{panic!("JSON mismatch case {i}")}checked.push(serde_json::json!({"case":i,"bytes":w.n}));}
 let target=&rows[1];let full=serde_json::to_vec(target).unwrap().len()as u64;
 let(ok,exact)=count(&WrappedRow(target),Some(full),0,None);let(limit,below)=count(&WrappedRow(target),Some(full-1),0,None);
 let(overflow,overflow_w)=count(&WrappedRow(target),None,u64::MAX-2,None);let(cancel,cancel_w)=count(&WrappedRow(target),None,0,Some(8));let(bad,bad_w)=count(&Broken,None,0,None);
 if ok.is_err()||exact.n!=full||limit.is_ok()||below.stop!=Some(Stop::OutputLimit)||overflow.is_ok()||overflow_w.stop!=Some(Stop::Overflow)||cancel.is_ok()||cancel_w.stop!=Some(Stop::Cancelled)||bad.is_ok()||bad_w.stop.is_some(){panic!("counter error classification mismatch")}
 let big=vec![Value::Bytes(Bytes((0..100_000).map(|i|(i%251)as u8).collect()))];
 let(old_peak,old_len)=measured(&big);let(new_peak,new_len)=measured(&WrappedRow(&big));
 if old_len!=new_len||old_peak<100_000||new_peak>=old_peak{panic!("allocator observation did not show expected difference")}
 println!("{}",serde_json::json!({"cases":checked,"exact_length":full,"limit_completed":below.n,"limit_class":"output_limit","overflow_class":"overflow","cancel_class":"cancelled","real_serializer_error":bad.unwrap_err().to_string(),"old_peak_bytes":old_peak,"new_peak_bytes":new_peak,"large_encoded_bytes":old_len,"scope":"single-thread prototype using locked serde_json; allocator counts process allocation during serialization only","profile_admitted":false}));
}
