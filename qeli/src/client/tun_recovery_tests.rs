use super::*;
use std::collections::VecDeque;
struct Model {
    observations: VecDeque<Result<Option<u32>, io::ErrorKind>>,
    owners: Vec<u32>,
    deletions: usize,
    pauses: usize,
    removed_by_delete: bool,
}
impl Model {
    fn new(observations: impl IntoIterator<Item = Result<Option<u32>, io::ErrorKind>>) -> Self {
        Self {
            observations: observations.into_iter().collect(),
            owners: vec![std::process::id()],
            deletions: 0,
            pauses: 0,
            removed_by_delete: false,
        }
    }
}
impl Host for Model {
    fn index(&mut self, _: &str) -> io::Result<Option<u32>> {
        if self.removed_by_delete && self.deletions > 0 {
            return Ok(None);
        }
        self.observations
            .pop_front()
            .unwrap_or(Ok(Some(7)))
            .map_err(Into::into)
    }
    fn pause(&mut self, duration: Duration) {
        assert_eq!(duration, Duration::from_millis(50));
        self.pauses += 1;
    }
}
#[test]
fn regression_partial_holder_list_never_authorizes_device_deletion() {
    let mut model = Model::new([Ok(Some(7))]);
    model.removed_by_delete = true;
    // Only our PID was visible; another owner could have been hidden by a failed proc read.
    assert!(prepare_with(&mut model, "vpn0", false).is_err());
    assert_eq!(model.deletions, 0);
    assert_eq!(model.owners, [std::process::id()]);
}
#[test]
fn regression_initial_observation_error_is_not_absence() {
    for error in [io::ErrorKind::PermissionDenied, io::ErrorKind::Other] {
        let mut model = Model::new([Err(error)]);
        assert!(prepare_with(&mut model, "vpn0", false).is_err());
        assert_eq!(model.deletions, 0);
        assert_eq!(model.pauses, 0);
    }
}
#[test]
fn regression_wait_observation_error_is_not_completed_recovery() {
    let mut model = Model::new([Ok(Some(7)), Err(io::ErrorKind::PermissionDenied)]);
    assert!(prepare_with(&mut model, "vpn0", false).is_err());
    assert_eq!(model.deletions, 0);
}
#[test]
fn regression_replaced_interface_is_not_the_previous_generation() {
    let mut model = Model::new([Ok(Some(7)), Ok(Some(8)), Ok(None)]);
    assert!(prepare_with(&mut model, "vpn0", false).is_err());
    assert_eq!(model.deletions, 0);
}
#[test]
fn absent_interface_allows_create_without_waiting() {
    let mut model = Model::new([Ok(None)]);
    prepare_with(&mut model, "vpn0", false).unwrap();
    assert_eq!(model.pauses, 0);
    assert_eq!(model.deletions, 0);
}
#[test]
fn attach_requires_existing_interface() {
    let mut model = Model::new([Ok(None)]);
    assert!(prepare_with(&mut model, "vpn0", true).is_err());
    let mut model = Model::new([Ok(Some(7))]);
    prepare_with(&mut model, "vpn0", true).unwrap();
    assert_eq!(model.pauses, 0);
    assert_eq!(model.deletions, 0);
}

#[test]
fn released_device_allows_create_without_any_delete_operation() {
    let mut model = Model::new([Ok(Some(7)), Ok(Some(7)), Ok(None)]);
    prepare_with(&mut model, "vpn0", false).unwrap();
    assert_eq!(model.pauses, 2);
    assert_eq!(model.deletions, 0);
}
#[test]
fn persistent_device_is_left_untouched_after_bounded_wait() {
    let mut model = Model::new([Ok(Some(7))]);
    assert!(prepare_with(&mut model, "vpn0", false)
        .unwrap_err()
        .to_string()
        .contains("still present"));
    assert_eq!(model.pauses, 120);
    assert_eq!(model.deletions, 0);
}
#[test]
fn release_on_last_observation_is_not_missed() {
    let mut model = Model::new(std::iter::repeat_n(Ok(Some(7)), 120).chain([Ok(None)]));
    prepare_with(&mut model, "vpn0", false).unwrap();
    assert_eq!(model.pauses, 120);
    assert_eq!(model.deletions, 0);
}
#[test]
fn attach_observation_error_never_becomes_permission_to_open() {
    let mut model = Model::new([Err(io::ErrorKind::PermissionDenied)]);
    assert!(prepare_with(&mut model, "vpn0", true)
        .unwrap_err()
        .to_string()
        .contains("cannot inspect"));
    assert_eq!(model.pauses, 0);
    assert_eq!(model.deletions, 0);
}
#[test]
fn creation_race_after_confirmed_absence_must_still_be_checked_by_ioctl() {
    let mut model = Model::new([Ok(None), Ok(Some(9))]);
    prepare_with(&mut model, "vpn0", false).unwrap();
    // Admission is just an observation, never a claim on the name. Exclusive ioctl
    // tests cover the final claim; the next observation can already see a newcomer.
    assert_eq!(model.index("vpn0").unwrap(), Some(9));
    assert_eq!(model.deletions, 0);
}
