/* Host unit · contained per-session symlink table (Tier-2 honey shell).
 * `just test-symlink-table-unit` */
#include <stdio.h>
#include <string.h>
#include <lucas/symlink_table.h>

#define CHECK(c) do{ if(!(c)){ printf("FAIL line %d: %s\n",__LINE__,#c); fails++; } else passes++; }while(0)

int main(void) {
    int fails = 0, passes = 0;

    /* add + get */
    CHECK(lucas_symlink_add(1, "/tmp/a", "/etc/passwd") == 0);
    CHECK(lucas_symlink_get(1, "/tmp/a") && strcmp(lucas_symlink_get(1, "/tmp/a"), "/etc/passwd") == 0);

    /* EEXIST on a duplicate link in the same session */
    CHECK(lucas_symlink_add(1, "/tmp/a", "/x") == -17);

    /* session isolation: session 2 cannot see session 1's link, same key OK */
    CHECK(lucas_symlink_get(2, "/tmp/a") == 0);
    CHECK(lucas_symlink_add(2, "/tmp/a", "/other") == 0);
    CHECK(strcmp(lucas_symlink_get(2, "/tmp/a"), "/other") == 0);

    /* relative target stored VERBATIM (readlink must return it literally) */
    CHECK(lucas_symlink_add(1, "/tmp/rel", "../up/foo") == 0);
    CHECK(strcmp(lucas_symlink_get(1, "/tmp/rel"), "../up/foo") == 0);

    /* reap drops only the named session */
    lucas_symlink_reap(1);
    CHECK(lucas_symlink_get(1, "/tmp/a") == 0);
    CHECK(lucas_symlink_get(1, "/tmp/rel") == 0);
    CHECK(lucas_symlink_get(2, "/tmp/a") && strcmp(lucas_symlink_get(2, "/tmp/a"), "/other") == 0);

    /* missing link → NULL */
    CHECK(lucas_symlink_get(9, "/tmp/none") == 0);

    printf("symlink_table host unit: %d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
