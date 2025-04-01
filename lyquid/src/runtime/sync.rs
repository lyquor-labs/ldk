use core::cell::UnsafeCell;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

// Directly call the host API because core::arch::wasm32 intrinsics are unstable
// without feature flags on the current toolchain, and we want to target Stable Rust.
// This matches the code that `shaker` (tools/src/lib.rs) would inject anyway
// (it replaces standard atomic instructions with calls to these host functions,
// passing the instruction's immediate offset as the last argument).
mod lyquor_api {
    #[link(wasm_import_module = "lyquor_api")]
    unsafe extern "C" {
        pub fn __wait(ptr: u32, exp: u32, timeout: i64, offset: u32) -> u32;
        pub fn __notify(ptr: u32, cnt: u32, offset: u32) -> u32;
    }
}

// ============================================================
// Mutex
// ============================================================

// 0: Unlocked
// 1: Locked (no known waiters)
// 2: Locked + Contended (waiters exist)
const MUTEX_UNLOCKED: u32 = 0;
const MUTEX_LOCKED: u32 = 1;
const MUTEX_CONTENDED: u32 = 2;

#[derive(Debug)]
pub struct Mutex<T: ?Sized> {
    state: AtomicU32,
    data: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(data: T) -> Self {
        Self {
            state: AtomicU32::new(MUTEX_UNLOCKED),
            data: UnsafeCell::new(data),
        }
    }
}

impl<T: ?Sized> Mutex<T> {
    #[inline]
    pub fn lock(&self) -> MutexGuard<'_, T> {
        // Fast path: uncontended acquire
        if self
            .state
            .compare_exchange(MUTEX_UNLOCKED, MUTEX_LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            self.lock_slow();
        }
        MutexGuard { lock: self }
    }

    #[cold]
    fn lock_slow(&self) {
        let mut s = self.state.load(Ordering::Relaxed);
        loop {
            // If unlocked, acquire pessimistically as CONTENDED to propagate wakeups.
            // This fixes the "multiple waiters" lost-wakeup deadlock.
            if s == MUTEX_UNLOCKED {
                match self
                    .state
                    .compare_exchange(MUTEX_UNLOCKED, MUTEX_CONTENDED, Ordering::Acquire, Ordering::Relaxed)
                {
                    Ok(_) => return, // Acquired
                    Err(e) => s = e,
                }
                continue;
            }

            // If locked (but not contended), try to mark as contended.
            if s == MUTEX_LOCKED {
                match self
                    .state
                    .compare_exchange(MUTEX_LOCKED, MUTEX_CONTENDED, Ordering::Relaxed, Ordering::Relaxed)
                {
                    Ok(_) => s = MUTEX_CONTENDED,
                    Err(e) => s = e,
                }
                continue;
            }

            // If contended, wait.
            unsafe {
                lyquor_api::__wait(self.state.as_ptr() as u32, MUTEX_CONTENDED, -1, 0);
            }
            s = self.state.load(Ordering::Relaxed);
        }
    }

    fn unlock(&self) {
        let prev = self.state.swap(MUTEX_UNLOCKED, Ordering::Release);
        if prev == MUTEX_CONTENDED {
            unsafe {
                lyquor_api::__notify(self.state.as_ptr() as u32, 1, 0);
            }
        }
    }
}

pub struct MutexGuard<'a, T: ?Sized> {
    lock: &'a Mutex<T>,
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<T: ?Sized + fmt::Display> fmt::Display for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

// ============================================================
// RwLock (writer-fair)
// ============================================================
//
// 1) Safety: mutual exclusion and reader/writer rules.
//
// Writer Exclusivity: If state == RWLOCK_WRITER, then no reader holds the lock and at most one writer holds it.
//
// Proof:
// - The only way to set state to RWLOCK_WRITER is compare_exchange_weak(0 -> WRITER). Once state
// == WRITER, no reader can increment the count because reader increment CAS is s -> s+1 where s
// must be a finite count; you explicitly wait when s == WRITER.
// - No other writer can set WRITER because state != 0. Writers only CAS from 0.
// So writer mutual exclusion holds.
//
// Readers Concurrent, with No Writer Concurrently: If 1 <= state <= RWLOCK_MAX_READERS, then there
// exists exactly state readers holding the lock, and no writer holds it.
//
// Proof:
// - Readers acquire the lock only via CAS s -> s+1 with s != WRITER and s <= MAX_READERS, and release via fetch_sub(1).
// - Writers can only acquire when state == 0.
// So readers can be concurrent and exclude writers.
//
// Gate Behavior: If writers_waiting != 0, new readers do not enter.
//
// Proof:
// In read(), before attempting to CAS-increment reader count, you load ww = writers_waiting.load()
// and if ww != 0 you wait on writers_waiting and retry. There is no other reader entry path.
// This is the fairness gate.
//
// 2) Progress: no deadlock or "lost wakeups".
//
// The key to "no deadlock" is to show: any thread that goes to sleep is sleeping on a condition
// that some other thread will eventually change and will __notify on the same address when that
// condition becomes favorable.
//
// - Wait site in `s == RWLOCK_WRITER`: reader waiting on active writer. The only way to leave
// state == WRITER is unlock_write() doing state.store(0, Release) and then __notify(state, cnt).
// So any reader sleeping here is guaranteed to be eligible to wake when the writer releases (the
// only transition that can help a reader). No lost wakeup here because if the writer unlocks
// before the reader calls __wait, then state != RWLOCK_WRITER and futex semantics make __wait
// return immediately (or not sleep).
//
// - Wait site in `ww != 0`: reader waiting on fairness gate (ww code). WriterQueueGuard::drop()
// does prev = writers_waiting.fetch_sub(1, AcqRel) and if prev == 1 (meaning it becomes 0) it
// calls __notify(writers_waiting, MAX). So any reader sleeping here is guaranteed to be woken
// when the gate opens (writers_waiting transitions to 0). No lost wakeup because if the last
// writer leaves the queue before the reader calls __wait, then writers_waiting != ww, so futex
// semantics prevent sleeping.
//
// - Wait site in `s != RWLOCK_UNLOCKED`: writer waiting on state (readers present or another
// writer holds). Writers sleep while state != 0 (either readers count or WRITER). We need to show
// that whenever state can become 0, there is a notify.
//
//   - Case 1: state is a reader count (> 0). The last reader to leave runs unlock_read(). So when
//   reader count transitions 1 -> 0, a notify is issued on state. That is exactly when a writer
//   may become eligible to acquire. Intermediate decrements do not notify, but they do not enable
//   writer acquisition, so they are not required for progress. No lost wakeup because if the last
//   reader leaves before the writer calls __wait(state, s), then state is no longer s and futex
//   semantics prevent sleeping.
//
//   - Case 2: state == WRITER. Then the holder must call unlock_write(), which stores 0 and
//   notifies on state. So writers cannot deadlock sleeping on state, because the only "unlocking"
//   transitions that enable them are notified.
//
//   - Remarks: The writer waits on the exact observed s, which might change from 5 to 4 to 3
//   without notifications. That's fine because writers only need to wake at the enabling
//   transition (1 -> 0 or WRITER -> 0) which is notified. A writer may "sleep longer than
//   necessary" relative to intermediate changes, but it will not sleep past the point where it
//   could acquire.

const RWLOCK_WRITER: u32 = u32::MAX;
const RWLOCK_UNLOCKED: u32 = 0;
const RWLOCK_MAX_READERS: u32 = u32::MAX - 2;

#[derive(Debug)]
pub struct RwLock<T: ?Sized> {
    state: AtomicU32,           // readers count or WRITER
    writers_waiting: AtomicU32, // fairness gate
    data: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send + Sync> Sync for RwLock<T> {}
unsafe impl<T: ?Sized + Send + Sync> Send for RwLock<T> {}

impl<T> RwLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            state: AtomicU32::new(RWLOCK_UNLOCKED),
            writers_waiting: AtomicU32::new(0),
            data: UnsafeCell::new(data),
        }
    }
}

// RAII guard to ensure writers_waiting is decremented even on panic/trap,
// AND to wake readers waiting on the gate when the last writer leaves.
struct WriterQueueGuard<'a>(&'a AtomicU32);

impl Drop for WriterQueueGuard<'_> {
    fn drop(&mut self) {
        let prev = self.0.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            // Gate just opened (writers_waiting -> 0). Wake all gated readers.
            unsafe {
                lyquor_api::__notify(self.0.as_ptr() as u32, u32::MAX, 0);
            }
        }
    }
}

impl<T: ?Sized> RwLock<T> {
    #[inline]
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        loop {
            let s = self.state.load(Ordering::Relaxed);

            // Active writer holds the lock
            if s == RWLOCK_WRITER {
                unsafe {
                    lyquor_api::__wait(self.state.as_ptr() as u32, RWLOCK_WRITER, -1, 0);
                }
                continue;
            }

            // Writer fairness gate: if any writer is queued, block new readers.
            let ww = self.writers_waiting.load(Ordering::Acquire);
            if ww != 0 {
                unsafe {
                    lyquor_api::__wait(self.writers_waiting.as_ptr() as u32, ww, -1, 0);
                }
                continue;
            }

            // Overflow protection (pathological)
            if s > RWLOCK_MAX_READERS {
                unsafe {
                    lyquor_api::__wait(self.state.as_ptr() as u32, s, -1, 0);
                }
                continue;
            }

            // Try to increment reader count
            match self
                .state
                .compare_exchange_weak(s, s + 1, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return RwLockReadGuard { lock: self },
                Err(_) => continue,
            }
        }
    }

    #[inline]
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.writers_waiting.fetch_add(1, Ordering::AcqRel);
        let _guard = WriterQueueGuard(&self.writers_waiting);

        loop {
            let s = self.state.load(Ordering::Relaxed);
            if s == RWLOCK_UNLOCKED {
                if self
                    .state
                    .compare_exchange_weak(RWLOCK_UNLOCKED, RWLOCK_WRITER, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    // _guard drops here: writers_waiting decremented, gate possibly opened.
                    return RwLockWriteGuard { lock: self };
                }
            } else {
                unsafe {
                    lyquor_api::__wait(self.state.as_ptr() as u32, s, -1, 0);
                }
            }
        }
    }

    fn unlock_read(&self) {
        let prev = self.state.fetch_sub(1, Ordering::Release);
        if prev == 1 {
            // last reader out: wake a waiting writer (or someone waiting on state)
            unsafe {
                lyquor_api::__notify(self.state.as_ptr() as u32, 1, 0);
            }
        }
    }

    fn unlock_write(&self) {
        self.state.store(RWLOCK_UNLOCKED, Ordering::Release);

        // Prefer waking writers; if none queued, wake all readers waiting on state
        let cnt = if self.writers_waiting.load(Ordering::Acquire) != 0 {
            1
        } else {
            u32::MAX
        };

        unsafe {
            lyquor_api::__notify(self.state.as_ptr() as u32, cnt, 0);
        }
    }
}

pub struct RwLockReadGuard<'a, T: ?Sized> {
    lock: &'a RwLock<T>,
}

impl<T: ?Sized> Deref for RwLockReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for RwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.unlock_read();
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for RwLockReadGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<T: ?Sized + fmt::Display> fmt::Display for RwLockReadGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

pub struct RwLockWriteGuard<'a, T: ?Sized> {
    lock: &'a RwLock<T>,
}

impl<T: ?Sized> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for RwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.unlock_write();
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for RwLockWriteGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<T: ?Sized + fmt::Display> fmt::Display for RwLockWriteGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}
