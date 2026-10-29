const std = @import("std");

pub const lifetime_seconds = 8 * 60 * 60;
const Session = struct { token: [32]u8, account: [32]u8, expires: i64 };
pub const Store = struct {
    mutex: std.atomic.Mutex = .unlocked,
    entries: [128]?Session = @splat(null),
    attempt_window: i64 = -1,
    attempts: usize = 0,

    fn lock(self: *Store) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    pub fn admitLogin(self: *Store, now: i64) bool {
        self.lock();
        defer self.mutex.unlock();
        if (now - self.attempt_window >= 10 or now < self.attempt_window) {
            self.attempt_window = now;
            self.attempts = 0;
        }
        if (self.attempts >= 10) return false;
        self.attempts += 1;
        return true;
    }

    pub fn issue(self: *Store, token: [32]u8, account: [32]u8, now: i64) !void {
        self.lock();
        defer self.mutex.unlock();
        for (&self.entries) |*entry| {
            if (entry.* == null or entry.*.?.expires <= now) {
                entry.* = .{ .token = token, .account = account, .expires = now + lifetime_seconds };
                return;
            }
        }
        return error.AdminSessionLimit;
    }

    pub fn valid(self: *Store, token: [32]u8, account: [32]u8, now: i64) bool {
        self.lock();
        defer self.mutex.unlock();
        for (self.entries) |entry| {
            const item = entry orelse continue;
            if (item.expires > now and std.crypto.timing_safe.eql([32]u8, token, item.token) and
                std.crypto.timing_safe.eql([32]u8, account, item.account)) return true;
        }
        return false;
    }

    pub fn revoke(self: *Store, token: [32]u8, account: [32]u8) void {
        self.lock();
        defer self.mutex.unlock();
        for (&self.entries) |*entry| {
            const item = entry.* orelse continue;
            if (std.crypto.timing_safe.eql([32]u8, token, item.token) and
                std.crypto.timing_safe.eql([32]u8, account, item.account)) entry.* = null;
        }
    }
};

pub var sessions = Store{};

test "admin sessions expire, revoke and bind to credential identity" {
    var store = Store{};
    const token = [_]u8{1} ** 32;
    const account = [_]u8{2} ** 32;
    try store.issue(token, account, 100);
    try std.testing.expect(store.valid(token, account, 101));
    try std.testing.expect(!store.valid(token, [_]u8{3} ** 32, 101));
    try std.testing.expect(!store.valid(token, account, 100 + lifetime_seconds));
    store.revoke(token, account);
    try std.testing.expect(!store.valid(token, account, 101));
    for (0..128) |i| {
        var unique = token;
        unique[0] = @intCast(i);
        try store.issue(unique, account, 200);
    }
    try std.testing.expectError(error.AdminSessionLimit, store.issue(token, account, 201));
    try store.issue(token, account, 200 + lifetime_seconds);
    for (0..10) |_| try std.testing.expect(store.admitLogin(200));
    try std.testing.expect(!store.admitLogin(200));
    try std.testing.expect(store.admitLogin(210));
}
