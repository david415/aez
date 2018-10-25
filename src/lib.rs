
pub mod fu;

#[cfg(test)]
mod tests {
    use super::fu::do_stuff;
    #[test]
    fn it_works() {
        do_stuff();
    }
}
