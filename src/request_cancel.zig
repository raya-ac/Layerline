const std = @import("std");

// The routing task owns this borrowed flag until its joined completion. Nested
// concurrent work must capture it explicitly, not rely on thread-local state.
pub threadlocal var active: ?*const std.atomic.Value(bool) = null;

pub fn check() error{Canceled}!void {
    if (active) |flag| if (flag.load(.acquire)) return error.Canceled;
}

test "request cancellation scopes restore without leaking into another task" {
    const previous = active;
    defer active = previous;
    var canceled = std.atomic.Value(bool).init(false);
    active = &canceled;
    try check();
    canceled.store(true, .release);
    try std.testing.expectError(error.Canceled, check());
    active = null;
    try check();
}
