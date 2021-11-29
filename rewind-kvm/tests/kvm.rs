
#[cfg(unix)]
#[cfg(test)]
mod test {

    use rewind_core::{mem, trace::{self, Trace, Tracer}};
    use mem::X64VirtualAddressSpace;
    use rewind_snapshot::FileSnapshot;
    use rewind_kvm::KvmTracer;

    use crate::TestHook;

    #[test]
    fn test_tracer() {

        let path = std::path::PathBuf::from("../examples/CVE-2020-17087/snapshots/17763.1.amd64fre.rs5_release.180914-1434/cng/ConfigIoHandler_Safeguarded");
        let snapshot = FileSnapshot::new(&path).unwrap();

        let context = trace::ProcessorState::load(path.join("context.json")).unwrap();

        let return_address = snapshot.read_gva_u64(context.cr3, context.rsp).unwrap();

        // let gpa = snapshot.translate_gva(context.cr3, return_address).unwrap();
        // println!("gpa is {:x}", gpa);

        let mut tracer = KvmTracer::new(snapshot).unwrap();
        
        let mut params = trace::Params::default();
        let mut hook = TestHook::default();

        params.return_address = return_address;
        params.save_context = true;

        tracer.set_state(&context).unwrap();
        tracer.enable_singlestep();

        let trace = tracer.run(&params, &mut hook).unwrap();
        println!("trace lasted {:?}", trace.end.unwrap() - trace.start.unwrap());

        let pagefaults = tracer.get_mapped_pages().unwrap();
        println!("got {} pagefault(s)", pagefaults);
        assert_eq!(pagefaults, 130);

        let modified_pages = tracer.get_dirty_pages().unwrap();
        assert_eq!(modified_pages.len(), 130);

        // let modified_pages = tracer.get_dirty_pages().unwrap();
        // assert_eq!(modified_pages.len(), 0);

        let state = tracer.get_state().unwrap();

        assert_eq!(state.rip, params.return_address);

        let expected = Trace::load(path.join("trace.json")).unwrap();

        assert_eq!(trace.seen.len(), expected.seen.len());
        assert_eq!(trace.coverage.len(), expected.coverage.len());

        assert_eq!(trace.status, trace::EmulationStatus::Success);

        assert_eq!(trace.coverage[0].0, context.rip);

        for (index, (addr, context)) in expected.coverage.iter().enumerate() {
            assert_eq!(*addr, trace.coverage[index].0, "index {}: rip {:x} vs {:x}", index, *addr, trace.coverage[index].0);
            if let Some(context) = context {
                let expected_context = trace.coverage[index].1.as_ref().unwrap();
                // rflags are different so they are not tested
                assert_eq!(context.rax, expected_context.rax);
                assert_eq!(context.rbx, expected_context.rbx);
                assert_eq!(context.rcx, expected_context.rcx);
                assert_eq!(context.rdx, expected_context.rdx);
                assert_eq!(context.rsi, expected_context.rsi);
                assert_eq!(context.rdi, expected_context.rdi);
                assert_eq!(context.rsp, expected_context.rsp);
                assert_eq!(context.rbp, expected_context.rbp);
                assert_eq!(context.r8, expected_context.r8);
                assert_eq!(context.r9, expected_context.r9);
                assert_eq!(context.r10, expected_context.r10);
                assert_eq!(context.r11, expected_context.r11);
                assert_eq!(context.r12, expected_context.r12);
                assert_eq!(context.r13, expected_context.r13);
                assert_eq!(context.r14, expected_context.r14);
                assert_eq!(context.r15, expected_context.r15);
                assert_eq!(context.rip, expected_context.rip, "rip");
                assert_eq!(*addr, expected_context.rip, "rip");

            }

            assert!(expected.seen.contains(addr));
            assert!(trace.seen.contains(addr));

        }

    }

    fn test_read_write_mem() {

        let path = std::path::PathBuf::from("../examples/CVE-2020-17087/snapshots/17763.1.amd64fre.rs5_release.180914-1434/cng/ConfigIoHandler_Safeguarded");
        let snapshot = FileSnapshot::new(&path).unwrap();

        let context = trace::ProcessorState::load(path.join("context.json")).unwrap();

        let return_address = snapshot.read_gva_u64(context.cr3, context.rsp).unwrap();

        let gpa = snapshot.translate_gva(context.cr3, return_address).unwrap();
        println!("gpa is {:x}", gpa);

        let mut tracer = KvmTracer::new(snapshot).unwrap();
        
        let data = &[0xcc];
        Tracer::write_gva(&mut tracer, context.cr3, return_address, data).unwrap();

        let mut expected = vec![0u8; 10];
        Tracer::read_gva(&mut tracer, context.cr3, return_address, &mut expected).unwrap();

        assert_eq!(expected, [0xcc, 0x8d, 0x9c, 0x24, 0xa0, 0, 0, 0, 0x49, 0x8b]);

        // let modified_pages = tracer.restore_snapshot().unwrap();
        // assert_eq!(modified_pages, 5);

    }
}
