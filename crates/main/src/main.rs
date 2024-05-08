mod unprivileged_main;

use utils::UnwrapFailure;

fn main() -> std::io::Result<()> {
    let mut helper = None;

    // Drop privileges if specified. If so, start the privileged helper before that.
    #[cfg(not(target_env = "msvc"))]
    {
        if let Ok(run_as_user) = std::env::var("RUN_AS_USER") {
            helper = Some(unsafe { bind_helper::start_privileged_helper() });

            let mut pd = privdrop::PrivDrop::default().user(run_as_user);
            if let Ok(run_as_group) = std::env::var("RUN_AS_GROUP") {
                pd = pd.group(run_as_group);
            }
            pd.apply().failed("Failed to drop privileges");
        }
    }

    unprivileged_main::unprivileged_main(helper)
}
