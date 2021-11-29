
mod common;

#[cfg(test)]
mod test {
    use rewind_bochs::BochsTracer;
    use rewind_core::{mem, trace::{self, Trace, Tracer}};
    use mem::X64VirtualAddressSpace;

    use super::common::*;

    #[test]
    fn test_tracer_sdb() {

        let path = std::path::PathBuf::from("tests/fixtures/sdb");
        let snapshot = TestSnapshot::default();

        let mut tracer = BochsTracer::new(&snapshot);
        let context = trace::ProcessorState::load(path.join("context.json")).unwrap();
        let mut params = trace::Params::default();
        let mut hook = TestHook::default();

        params.return_address = snapshot.read_gva_u64(context.cr3, context.rsp).unwrap();
        params.save_context = true;

        tracer.set_state(&context).unwrap();
        let trace = tracer.run(&params, &mut hook).unwrap();

        // trace.save(path.join("saved.json")).unwrap();

        let expected = Trace::load(path.join("expected.json")).unwrap();

        for (index, (addr, context)) in expected.coverage.iter().enumerate() {
            assert_eq!(*addr, trace.coverage[index].0);
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
                assert_eq!(context.rip, expected_context.rip);
                assert_eq!(*addr, expected_context.rip);

            }

            assert!(expected.seen.contains(addr));
            assert!(trace.seen.contains(addr));

        }

        assert_eq!(trace.seen.len(), 2913);
        assert_eq!(trace.coverage.len(), 59120);
        assert_eq!(trace.immediates.len(), 22);
        assert_eq!(trace.mem_accesses.len(), 16650);

        assert_eq!(trace.status, trace::EmulationStatus::Success);

        assert_eq!(trace.coverage[0].0, context.rip);

        let state = tracer.get_state().unwrap();

        assert_eq!(state.rip, params.return_address);

        let pages = tracer.get_mapped_pages().unwrap();

        assert_eq!(pages, 80);

    }

}