use sqlparser::{dialect::GenericDialect, parser::Parser};

fn main() {
    let dialect = GenericDialect {};
    let sql = "SELECT CAST(value AS TEXT) AS t FROM strings WHERE value LIKE '%_%' ESCAPE '\\'";
    let statements = Parser::new(&dialect)
        .with_recursion_limit(32)
        .try_with_sql(sql)
        .unwrap()
        .parse_statements()
        .unwrap();
    assert_eq!(statements.len(), 1);
    let rendered = statements[0].to_string();
    assert_eq!(Parser::parse_sql(&dialect, &rendered).unwrap(), statements);
    println!("sqlparser 0.63.0 std-only; CAST/LIKE/ESCAPE AST roundtrip passed; no SQL execution or profile qualification");
}
