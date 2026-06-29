#ifndef LUCAS_APT_TREE_SEED_H
#define LUCAS_APT_TREE_SEED_H
/* apt arc P0 · seeded /etc/apt config (the /var/lib/apt + /var/cache/apt dirs are
 * created empty by apt_tree_seed()). Keep in sync with src/test/sotOs-apt/etc/apt/. */
static const char apt_sources_list[] = "deb [trusted=yes] http://deb.debian.org/debian trixie main\n";
static const char apt_conf_99sotos[] =
    "Acquire::Languages \"none\";\n"
    "APT::Install-Recommends \"false\";\n"
    /* Pin the arch so libapt-pkg does NOT shell out to dpkg / read the cputable to
     * autodetect it (sotOs ships no /usr/share/dpkg/cputable → "E: Error reading
     * the CPU table" on apt-get -h).  amd64 matches the staged glibc closure. */
    "APT::Architecture \"amd64\";\n";
#endif /* LUCAS_APT_TREE_SEED_H */
