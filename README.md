# checkssl

> Check SSL certificate

## Example
```rust
use checkssl::CheckSSL;

let certificate = CheckSSL::from_domain_with_port("rust-lang.org", "443").unwrap();
println!("{:?}", certificate)

```

## License
MIT @Aldi Priya Perdana