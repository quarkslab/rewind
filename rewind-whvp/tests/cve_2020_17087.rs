
mod common;

#[cfg(windows)]
#[cfg(test)]
mod test {

    use std::{fs::File, io::Read, path::PathBuf};

    use flate2::read::GzDecoder;
    use rewind_core::{mem::X64VirtualAddressSpace, trace::{self, CoverageMode, Trace, Tracer}};
    use rewind_snapshot::FileSnapshot;
    use rewind_whvp::WhvpTracer;
    use tar::Archive;

    use super::common::TestHook;

    // FIXME: need to test singlestep, bp, hit tracing, read/write memory
    // FIXME: test with input
    #[test]
    fn test_tracer_cve_2020_17087() {
        let path = PathBuf::from("../examples/CVE-2020-17087/snapshots/17763.1.amd64fre.rs5_release.180914-1434/cng/ConfigIoHandler_Safeguarded");
        let snapshot = FileSnapshot::new(&path).unwrap();

        let context = trace::ProcessorState::load(path.join("context.json")).unwrap();

        let return_address = snapshot.read_gva_u64(context.cr3, context.rsp).unwrap();

        let mut tracer = WhvpTracer::new(&snapshot).unwrap();
        
        let mut params = trace::Params::default();
        let mut hook = TestHook::default();

        params.return_address = return_address;
        params.save_context = true;
        params.coverage_mode = CoverageMode::None;

        tracer.set_state(&context).unwrap();

        let trace = tracer.run(&params, &mut hook).unwrap();

        let pagefaults = tracer.get_mapped_pages().unwrap();
        assert_eq!(pagefaults, 130);

        let state = tracer.get_state().unwrap();

        assert_eq!(state.rip, params.return_address);

        assert_eq!(trace.coverage.len(), 1);

        tracer.set_state(&context).unwrap();
        tracer.restore_snapshot().unwrap();

        params.coverage_mode = CoverageMode::Instrs;
        let trace = tracer.run(&params, &mut hook).unwrap();

        let path = PathBuf::from("tests/fixtures/CVE-2020-17087");
        let expected = Trace::load(path.join("expected.json")).unwrap();

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

        let _pages = tracer.restore_snapshot().unwrap();
        tracer.set_state(&context).unwrap();

        // load and write input
        let desc = path.join("input.yaml");
        let input_desc = rewind_core::mutation::InputDesc::load(desc).unwrap();

        let cr3 = context.cr3;

        let filename = path.join("repro.bin");
        let mut file = std::fs::File::open(filename).unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();

        for item in input_desc.items { 
            let slice = &buffer[item.offset..item.offset+item.size];
            Tracer::write_gva(&mut tracer, cr3, item.address, slice).unwrap();
        }

        params.excluded_addresses.insert("KiGeneralProtectionFaultShadow".into(), 0xfffff8051a3cc780);

        let trace = tracer.run(&params, &mut hook).unwrap();
        let state = tracer.get_state().unwrap();

        // ntkrnlmp!KiGeneralProtectionFaultShadow
        // fffff8051a3cc780 f644241001                      test byte ptr [rsp+0x10], 0x01
        assert_eq!(state.rip, 0xfffff8051a3cc780);

        let path = PathBuf::from("tests/fixtures/CVE-2020-17087");
        let tar_gz = File::open(path.join("expected_with_crash.json.tar.gz")).unwrap();
        let tar = GzDecoder::new(tar_gz);
        let mut archive = Archive::new(tar);
        archive.unpack(&path).unwrap();

        let expected = Trace::load(path.join("expected_with_crash.json")).unwrap();

        std::fs::remove_file(path.join("expected_with_crash.json")).unwrap();

        assert_eq!(trace.seen.len(), expected.seen.len());
        assert_eq!(trace.coverage.len(), expected.coverage.len());

        let msg = "KiGeneralProtectionFaultShadow".into();
        assert_eq!(trace.status, trace::EmulationStatus::ForbiddenAddress(msg));

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

}