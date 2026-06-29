add_executable(sotOs-shell
    main.c
    readline.c
    history.c
    completion.c
    parser.c
    glob.c
    sotnano.c)

target_include_directories(sotOs-shell PRIVATE
    ${CMAKE_SOURCE_DIR}/include)

# Headless demo profile.  Default LEAN: the scripted demo_commands[] runs only
# the cheap core (deception narrative + observability markers + bbsh-auto), so
# every gate that does NOT need a completed-arc demo boots fast.  The heavy
# completed-arc proofs (GUI/wayland/Doom, compat-host probes, subsystem
# self-tests, TCC/churn/persistence) are wrapped in FULL(...) and only run when
# SOTOS_DEMO_FULL=ON — the arc-specific gates that grep those markers
# reconfigure with -DSOTOS_DEMO_FULL=ON (mirrors the SOTOS_FS_GATE pattern).
option(SOTOS_DEMO_FULL "Run the full completed-arc demo battery at headless boot" OFF)
if(SOTOS_DEMO_FULL)
    target_compile_definitions(sotOs-shell PRIVATE SOTOS_DEMO_FULL=1)
endif()

target_link_libraries(sotOs-shell
    sotos-string
    sel4
    muslc
    sel4muslcsys
    sel4debug
    utils)
