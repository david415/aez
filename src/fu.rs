
extern {
    fn resetAMD64SSE2();
}

pub fn do_stuff() {
    unsafe {
        resetAMD64SSE2();
    }
}
