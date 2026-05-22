#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Build:
 *   gcc -Wall -Wextra -O0 -g -pthread multithread_debug_test.c -o multithread_debug_test
 *
 * Run:
 *   ./multithread_debug_test
 *
 * Debugger ideas:
 *   - Break on each thread_* function.
 *   - Inspect named threads with "info threads" in gdb.
 *   - Step through mutex, condvar, rwlock, recursion, atomics, and heap paths.
 */

enum {
    THREAD_COUNT = 6,
    QUEUE_CAPACITY = 8,
    LOOP_COUNT = 12,
    PRODUCER_ITEMS = 18
};

typedef struct {
    int values[QUEUE_CAPACITY];
    int head;
    int tail;
    int count;
    bool done;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} int_queue_t;

typedef struct heap_node {
    int value;
    char label[24];
    struct heap_node *next;
} heap_node_t;

typedef struct {
    int version;
    char mode[32];
    unsigned checksum;
} shared_config_t;

static pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t config_lock = PTHREAD_RWLOCK_INITIALIZER;
static atomic_int start_gate = 0;
static atomic_int heartbeat = 0;
static atomic_long fibonacci_total = 0;

static int shared_counter = 0;
static int_queue_t queue_state = {
    .head = 0,
    .tail = 0,
    .count = 0,
    .done = false,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .not_empty = PTHREAD_COND_INITIALIZER,
    .not_full = PTHREAD_COND_INITIALIZER,
};
static shared_config_t shared_config = {
    .version = 1,
    .mode = "boot",
    .checksum = 0x1234u,
};

static void fail_pthread(int err, const char *what)
{
    if (err == 0) {
        return;
    }

    fprintf(stderr, "%s: %s\n", what, strerror(err));
    exit(EXIT_FAILURE);
}

static void set_thread_name(const char *name)
{
#if defined(__linux__)
    int err = pthread_setname_np(pthread_self(), name);
    if (err != 0 && err != ERANGE) {
        fprintf(stderr, "pthread_setname_np(%s): %s\n", name, strerror(err));
    }
#else
    (void)name;
#endif
}

static void wait_for_start_gate(void)
{
    while (atomic_load_explicit(&start_gate, memory_order_acquire) == 0) {
        usleep(1000);
    }
}

static void tiny_pause(unsigned multiplier)
{
    usleep(15000u + (multiplier % 5u) * 7000u);
}

static int transform_counter_value(int value, int iteration)
{
    int rotated = (value << 1) ^ (iteration * 17);
    int folded = rotated ^ (rotated >> 3);
    return folded & 0x7fffffff;
}

static long fibonacci_recursive(int n)
{
    if (n <= 1) {
        return n;
    }

    return fibonacci_recursive(n - 1) + fibonacci_recursive(n - 2);
}

static unsigned config_checksum(int version, const char *mode)
{
    unsigned hash = 2166136261u;
    const unsigned char *cursor = (const unsigned char *)mode;

    hash ^= (unsigned)version;
    hash *= 16777619u;

    while (*cursor != '\0') {
        hash ^= (unsigned)*cursor++;
        hash *= 16777619u;
    }

    return hash;
}

static void queue_push(int_queue_t *queue, int value)
{
    fail_pthread(pthread_mutex_lock(&queue->mutex), "pthread_mutex_lock(queue)");

    while (queue->count == QUEUE_CAPACITY) {
        fail_pthread(pthread_cond_wait(&queue->not_full, &queue->mutex),
                     "pthread_cond_wait(not_full)");
    }

    queue->values[queue->tail] = value;
    queue->tail = (queue->tail + 1) % QUEUE_CAPACITY;
    queue->count++;

    fail_pthread(pthread_cond_signal(&queue->not_empty), "pthread_cond_signal(not_empty)");
    fail_pthread(pthread_mutex_unlock(&queue->mutex), "pthread_mutex_unlock(queue)");
}

static bool queue_pop(int_queue_t *queue, int *value)
{
    fail_pthread(pthread_mutex_lock(&queue->mutex), "pthread_mutex_lock(queue)");

    while (queue->count == 0 && !queue->done) {
        fail_pthread(pthread_cond_wait(&queue->not_empty, &queue->mutex),
                     "pthread_cond_wait(not_empty)");
    }

    if (queue->count == 0 && queue->done) {
        fail_pthread(pthread_mutex_unlock(&queue->mutex), "pthread_mutex_unlock(queue)");
        return false;
    }

    *value = queue->values[queue->head];
    queue->head = (queue->head + 1) % QUEUE_CAPACITY;
    queue->count--;

    fail_pthread(pthread_cond_signal(&queue->not_full), "pthread_cond_signal(not_full)");
    fail_pthread(pthread_mutex_unlock(&queue->mutex), "pthread_mutex_unlock(queue)");
    return true;
}

static void queue_mark_done(int_queue_t *queue)
{
    fail_pthread(pthread_mutex_lock(&queue->mutex), "pthread_mutex_lock(queue)");
    queue->done = true;
    fail_pthread(pthread_cond_broadcast(&queue->not_empty),
                 "pthread_cond_broadcast(not_empty)");
    fail_pthread(pthread_mutex_unlock(&queue->mutex), "pthread_mutex_unlock(queue)");
}

static void *thread_counter_worker(void *arg)
{
    int local_history[LOOP_COUNT];
    int thread_slot = *(int *)arg;

    set_thread_name("dbg-counter");
    wait_for_start_gate();

    for (int i = 0; i < LOOP_COUNT; i++) {
        fail_pthread(pthread_mutex_lock(&counter_mutex), "pthread_mutex_lock(counter)");
        shared_counter += 1 + (i % 3);
        local_history[i] = transform_counter_value(shared_counter, i);
        printf("[counter] slot=%d iter=%d shared=%d transformed=%d\n",
               thread_slot, i, shared_counter, local_history[i]);
        fail_pthread(pthread_mutex_unlock(&counter_mutex), "pthread_mutex_unlock(counter)");

        atomic_fetch_add_explicit(&heartbeat, 1, memory_order_relaxed);
        tiny_pause((unsigned)i);
    }

    return (void *)(intptr_t)local_history[LOOP_COUNT - 1];
}

static void *thread_fibonacci_worker(void *arg)
{
    int thread_slot = *(int *)arg;
    long local_total = 0;

    set_thread_name("dbg-fib");
    wait_for_start_gate();

    for (int n = 20; n < 25; n++) {
        long value = fibonacci_recursive(n);
        local_total += value;
        atomic_fetch_add_explicit(&fibonacci_total, value, memory_order_relaxed);
        printf("[fib] slot=%d n=%d value=%ld local_total=%ld\n",
               thread_slot, n, value, local_total);
        tiny_pause((unsigned)n);
    }

    return (void *)(intptr_t)(local_total & 0x7fffffff);
}

static void *thread_producer_worker(void *arg)
{
    int thread_slot = *(int *)arg;

    set_thread_name("dbg-producer");
    wait_for_start_gate();

    for (int i = 0; i < PRODUCER_ITEMS; i++) {
        int value = 1000 + i * 7;
        queue_push(&queue_state, value);
        printf("[producer] slot=%d item=%d value=%d\n", thread_slot, i, value);
        atomic_fetch_add_explicit(&heartbeat, 1, memory_order_relaxed);
        tiny_pause((unsigned)(i + 2));
    }

    queue_mark_done(&queue_state);
    return (void *)(intptr_t)PRODUCER_ITEMS;
}

static void *thread_consumer_worker(void *arg)
{
    int thread_slot = *(int *)arg;
    int consumed = 0;
    long sum = 0;

    set_thread_name("dbg-consumer");
    wait_for_start_gate();

    for (;;) {
        int value = 0;
        if (!queue_pop(&queue_state, &value)) {
            break;
        }

        consumed++;
        sum += value;
        printf("[consumer] slot=%d consumed=%d value=%d sum=%ld\n",
               thread_slot, consumed, value, sum);
        atomic_fetch_add_explicit(&heartbeat, 1, memory_order_relaxed);
        tiny_pause((unsigned)value);
    }

    return (void *)(intptr_t)(sum & 0x7fffffff);
}

static void *thread_config_worker(void *arg)
{
    static const char *modes[] = {
        "idle",
        "scan",
        "trace",
        "breakpoint",
        "single-step",
        "shutdown",
    };
    int thread_slot = *(int *)arg;

    set_thread_name("dbg-rwlock");
    wait_for_start_gate();

    for (int i = 0; i < LOOP_COUNT; i++) {
        if ((i % 3) == 0) {
            const char *next_mode = modes[(unsigned)i % (sizeof(modes) / sizeof(modes[0]))];

            fail_pthread(pthread_rwlock_wrlock(&config_lock), "pthread_rwlock_wrlock");
            shared_config.version++;
            snprintf(shared_config.mode, sizeof(shared_config.mode), "%s", next_mode);
            shared_config.checksum = config_checksum(shared_config.version, shared_config.mode);
            printf("[config-w] slot=%d version=%d mode=%s checksum=%u\n",
                   thread_slot, shared_config.version, shared_config.mode,
                   shared_config.checksum);
            fail_pthread(pthread_rwlock_unlock(&config_lock), "pthread_rwlock_unlock");
        } else {
            shared_config_t snapshot;

            fail_pthread(pthread_rwlock_rdlock(&config_lock), "pthread_rwlock_rdlock");
            snapshot = shared_config;
            fail_pthread(pthread_rwlock_unlock(&config_lock), "pthread_rwlock_unlock");

            printf("[config-r] slot=%d version=%d mode=%s checksum=%u\n",
                   thread_slot, snapshot.version, snapshot.mode, snapshot.checksum);
        }

        atomic_fetch_add_explicit(&heartbeat, 1, memory_order_relaxed);
        tiny_pause((unsigned)(i + 3));
    }

    return (void *)(intptr_t)shared_config.version;
}

static heap_node_t *make_heap_node(int index, heap_node_t *next)
{
    heap_node_t *node = malloc(sizeof(*node));
    if (node == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    node->value = index * index;
    snprintf(node->label, sizeof(node->label), "node-%02d", index);
    node->next = next;
    return node;
}

static int inspect_heap_list(heap_node_t *head)
{
    int score = 0;

    for (heap_node_t *cursor = head; cursor != NULL; cursor = cursor->next) {
        score += cursor->value + (int)strlen(cursor->label);
    }

    return score;
}

static void free_heap_list(heap_node_t *head)
{
    while (head != NULL) {
        heap_node_t *next = head->next;
        memset(head, 0xa5, sizeof(*head));
        free(head);
        head = next;
    }
}

static void *thread_heap_worker(void *arg)
{
    int thread_slot = *(int *)arg;
    int final_score = 0;

    set_thread_name("dbg-heap");
    wait_for_start_gate();

    for (int round = 0; round < 5; round++) {
        heap_node_t *head = NULL;

        for (int i = 0; i < 6; i++) {
            head = make_heap_node(round * 10 + i, head);
        }

        final_score = inspect_heap_list(head);
        printf("[heap] slot=%d round=%d score=%d head=%p\n",
               thread_slot, round, final_score, (void *)head);
        free_heap_list(head);

        atomic_fetch_add_explicit(&heartbeat, 1, memory_order_relaxed);
        tiny_pause((unsigned)(round + 4));
    }

    return (void *)(intptr_t)final_score;
}

int main(void)
{
    pthread_t threads[THREAD_COUNT];
    int slots[THREAD_COUNT] = {0, 1, 2, 3, 4, 5};
    void *(*workers[THREAD_COUNT])(void *) = {
        thread_counter_worker,
        thread_fibonacci_worker,
        thread_producer_worker,
        thread_consumer_worker,
        thread_config_worker,
        thread_heap_worker,
    };

    puts("creating 6 debugger test threads");
    for (int i = 0; i < THREAD_COUNT; i++) {
        int err = pthread_create(&threads[i], NULL, workers[i], &slots[i]);
        fail_pthread(err, "pthread_create");
    }

    puts("releasing start gate");
    atomic_store_explicit(&start_gate, 1, memory_order_release);

    for (int i = 0; i < THREAD_COUNT; i++) {
        void *result = NULL;
        int err = pthread_join(threads[i], &result);
        fail_pthread(err, "pthread_join");
        printf("[main] joined slot=%d result=%ld\n", i, (long)(intptr_t)result);
    }

    printf("[main] final shared_counter=%d heartbeat=%d fibonacci_total=%ld config_version=%d\n",
           shared_counter,
           atomic_load_explicit(&heartbeat, memory_order_relaxed),
           atomic_load_explicit(&fibonacci_total, memory_order_relaxed),
           shared_config.version);

    return EXIT_SUCCESS;
}
