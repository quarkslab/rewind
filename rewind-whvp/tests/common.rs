
use rewind_core::trace;

#[derive(Default)]
pub struct TestHook {

}

impl trace::Hook for TestHook {
    fn setup<T: trace::Tracer>(&mut self, _tracer: &mut T) {

    }

    fn handle_breakpoint<T: trace::Tracer>(&mut self, _tracer: &mut T) -> Result<bool, trace::TracerError> {
        todo!()
    }

    fn handle_trace(&self, _trace: &mut trace::Trace) -> Result<bool, trace::TracerError> {
        Ok(true)
    }

    fn patch_page(&self, _: u64) -> bool {
        todo!()
    }
}

