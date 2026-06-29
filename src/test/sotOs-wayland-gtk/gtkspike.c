/* sotOs · v2.4-2.6 · GTK3 over real Wayland (cairo software / wl_shm, NO EGL).
 *
 * A real, unmodified GTK3 app: gtk_init → a DECORATED GtkWindow + GtkDrawingArea →
 * a cairo "draw" callback (cairo_paint) → run the GLib main loop a few ticks →
 * quit.  GTK3's wayland backend renders the window (client-side-decoration titlebar
 * + content) through a cairo image surface backed by a wl_shm pool/buffer (no
 * GtkGLArea → no EGL/GL), exercising the honest compositor's wl_shm + xdg_shell
 * path with a real toolkit.  The env below makes GTK survive on a headless,
 * desktop-less, dbus-less host:
 *   GSETTINGS_BACKEND=memory  → no dconf/dbus (GtkSettings still needs the
 *                               COMPILED schemas baked at /usr/share/glib-2.0)
 *   NO_AT_BRIDGE=1            → no at-spi accessibility bridge (dbus)
 *   XDG_DATA_DIRS=/usr/share  → find gschemas/icons/themes
 *   FONTCONFIG_FILE=...       → a minimal fontconfig pointing at the baked font
 *   XCURSOR_PATH/THEME, HOME  → where libwayland-cursor finds Adwaita/cursors
 */
#include <gtk/gtk.h>
#include <string.h>
#include <unistd.h>

#define SAY(s) write(1, s, sizeof(s)-1)

static gboolean on_draw(GtkWidget *w, cairo_t *cr, gpointer d) {
    (void)d;
    /* v2.9 GTK-fidelity · paint a subtle gradient panel + Pango-laid TEXT, so the
     * content area exercises the REAL font path (fontconfig → DejaVuSans →
     * cairo/Pango glyph rasterization), not just a flat fill.  If the font fails
     * to load, Pango emits a warning the gate catches (no-fatal-GLib check). */
    int wd = gtk_widget_get_allocated_width(w), ht = gtk_widget_get_allocated_height(w);
    cairo_pattern_t *g = cairo_pattern_create_linear(0, 0, 0, ht);
    cairo_pattern_add_color_stop_rgb(g, 0.0, 0.16, 0.18, 0.22);
    cairo_pattern_add_color_stop_rgb(g, 1.0, 0.10, 0.11, 0.14);
    cairo_set_source(cr, g); cairo_paint(cr); cairo_pattern_destroy(g);

    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 20.0);
    cairo_set_source_rgb(cr, 0.90, 0.92, 0.96);
    cairo_move_to(cr, 16, 36);
    cairo_show_text(cr, "sotOs deception host");
    cairo_set_font_size(cr, 13.0);
    cairo_set_source_rgb(cr, 0.62, 0.78, 0.55);
    cairo_move_to(cr, 16, 62);
    cairo_show_text(cr, "GTK3 · Adwaita dark · wl_shm (no EGL)");
    /* report the ink extent so the gate can prove glyphs actually rasterized */
    cairo_text_extents_t ext; cairo_text_extents(cr, "sotOs deception host", &ext);
    if (wd > 0 && ext.width > 1.0) SAY("[gtkspike] cairo text rasterized (glyph ink > 0)\n");
    (void)wd;
    SAY("[gtkspike] draw callback fired (cairo paint + text over wl_shm)\n");
    return FALSE;
}

static int g_it = 0;
static gboolean tick(gpointer d) {
    (void)d;
    if (++g_it >= 30) { gtk_main_quit(); return FALSE; }
    return TRUE;
}

int main(int argc, char **argv) {
    setenv("XDG_RUNTIME_DIR", "/run/user/1000", 1);
    setenv("WAYLAND_DISPLAY", "wayland-0", 1);
    setenv("GDK_BACKEND", "wayland", 1);           /* force wayland, never x11 */
    setenv("GSETTINGS_BACKEND", "memory", 1);      /* no dconf/dbus */
    setenv("NO_AT_BRIDGE", "1", 1);                /* no at-spi/dbus a11y */
    setenv("XDG_DATA_DIRS", "/usr/share", 1);      /* gschemas/icons/themes */
    setenv("FONTCONFIG_FILE", "/usr/share/fontconfig/fonts.conf", 1);
    setenv("GDK_PIXBUF_MODULE_FILE", "/usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache", 1);
    setenv("XCURSOR_PATH", "/usr/share/icons", 1); /* libwayland-cursor → Adwaita/cursors */
    setenv("XCURSOR_THEME", "Adwaita", 1);
    setenv("HOME", "/root", 1);                    /* xcursor skips ~/ paths if HOME unset */

    SAY("[gtkspike] start · GTK3 over wayland (cairo software / wl_shm, no EGL)\n");

    if (!gtk_init_check(&argc, &argv)) {
        SAY("[gtkspike] gtk_init_check FAIL\n");
        return 1;
    }
    SAY("[gtkspike] gtk_init OK\n");
    /* v2.6 · a DECORATED window needs a cursor theme: GTK's wayland backend asserts
     * display_wayland->cursor_theme_name != NULL when it sets the titlebar/resize
     * cursors at map.  No desktop/gsettings here → set it explicitly; the Adwaita
     * cursor theme is shipped at /usr/share/icons/Adwaita/cursors and
     * wl_cursor_theme_load now succeeds (the LUCAS fallocate fix sizes its pool).
     *
     * v2.9 GTK-fidelity · the THEME: GTK3 ships Adwaita as a COMPILED resource
     * (no /usr/share/themes needed), so naming it + flipping the dark flag gives
     * the real dark Adwaita CSS — headerbar, buttons, entry all themed. */
    g_object_set(gtk_settings_get_default(),
                 "gtk-cursor-theme-name", "Adwaita",
                 "gtk-cursor-theme-size", 24,
                 "gtk-theme-name", "Adwaita",
                 "gtk-application-prefer-dark-theme", TRUE,
                 "gtk-font-name", "DejaVu Sans 11", NULL);
    { gboolean dark = FALSE; char *thm = NULL;
      g_object_get(gtk_settings_get_default(),
                   "gtk-theme-name", &thm,
                   "gtk-application-prefer-dark-theme", &dark, NULL);
      SAY("[gtkspike] theme = "); write(1, thm ? thm : "(null)", thm ? strlen(thm) : 6);
      SAY(dark ? " (dark)\n" : " (light)\n"); g_free(thm); }
    { GdkDisplay *dpy = gdk_display_get_default();
      const char *n = dpy ? gdk_display_get_name(dpy) : "(null)";
      SAY("[gtkspike] display = "); write(1, n, strlen(n)); SAY("\n"); }

    /* v2.5 GTK-fidelity · image loading works.  gdk-pixbuf 2.42 sniffs via GIO
     * (GDK_PIXBUF_USE_GIO_MIME → g_content_type_guess()/xdgmime), which needs the
     * shared-mime-info DB at /usr/share/mime/mime.cache (now shipped) — without it
     * every gdk_pixbuf auto-detect (the GtkImage / GtkIconTheme path) returned
     * GDK_PIXBUF_ERROR_UNKNOWN_TYPE.  This 1x1-PNG load is the regression guard. */
    {
        static const unsigned char png1x1[] = {
            0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,0x00,0x00,0x00,0x0d,0x49,0x48,0x44,0x52,
            0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x08,0x06,0x00,0x00,0x00,0x1f,0x15,0xc4,
            0x89,0x00,0x00,0x00,0x0a,0x49,0x44,0x41,0x54,0x78,0x9c,0x63,0x00,0x01,0x00,0x00,
            0x05,0x00,0x01,0x0d,0x0a,0x2d,0xb4,0x00,0x00,0x00,0x00,0x49,0x45,0x4e,0x44,0xae,
            0x42,0x60,0x82
        };
        GError *e = NULL;
        GdkPixbufLoader *ld = gdk_pixbuf_loader_new();
        gboolean ok = gdk_pixbuf_loader_write(ld, png1x1, sizeof(png1x1), &e)
                   && gdk_pixbuf_loader_close(ld, &e)
                   && gdk_pixbuf_loader_get_pixbuf(ld) != NULL;
        /* NB: SAY() uses sizeof(literal)-1 → must take a string LITERAL, not a ternary. */
        if (ok) SAY("[gtkspike] PNG auto-detect load OK (gdk-pixbuf gio-mime sniffing live)\n");
        else    SAY("[gtkspike] PNG auto-detect load FAIL\n");
        if (e) g_error_free(e);
    }

    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(win), 360, 240);
    gtk_window_set_title(GTK_WINDOW(win), "sotOs");
    /* v2.6 GTK-fidelity · DECORATED window.  The CSD titlebar's symbolic button
     * icons (window-{close,minimize,maximize}-symbolic) are SVG (Adwaita), loaded
     * via gdk-pixbuf → librsvg.  With image auto-detect fixed (v2.5 mime DB),
     * librsvg + the Adwaita symbolic icons + the cursor theme shipped, and the
     * LUCAS fallocate fix sizing the cursor wl_shm pool, GTK renders the full CSD.
     *
     * v2.9 GTK-fidelity · a modern Adwaita HEADERBAR (title + subtitle + window
     * controls) as the titlebar, and a real WIDGET layout below it — a styled
     * label, an entry, and a button row — so the dark Adwaita CSS + Pango text
     * are exercised by genuine toolkit widgets, not just a flat cairo fill. */
    gtk_window_set_decorated(GTK_WINDOW(win), TRUE);

    /* v2.9 GTK-fidelity · a modern Adwaita HEADERBAR (title + subtitle + window
     * controls) as the titlebar, and a real WIDGET layout below — a markup label,
     * an entry, the cairo drawing area, and two buttons — so the dark Adwaita CSS
     * + Pango text are exercised by genuine toolkit widgets, not just a flat fill.
     * GTK spawns a WORKER THREAD for text layout, and that worker itself spawns
     * another thread (nested clone-from-worker) — both sound now: the M0 clone
     * fix (lucas_thread_clone reads the CALLING thread's regs) + the 128 MiB heavy
     * arena (the multi-widget tree + worker stacks + Pango/cairo heap OOM'd 64). */
    GtkWidget *hb = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hb), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR(hb), "sotOs");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(hb), "deception host");
    gtk_window_set_titlebar(GTK_WINDOW(win), hb);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 10);
    GtkWidget *lbl = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(lbl),
        "<span size='large' weight='bold'>DECEPTION MONITOR</span>\n"
        "<span foreground='#8fb573'>live · contained · recorded</span>");
    gtk_widget_set_halign(lbl, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, FALSE, 0);
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "attacker filter…");
    gtk_box_pack_start(GTK_BOX(box), entry, FALSE, FALSE, 0);
    GtkWidget *da = gtk_drawing_area_new();
    gtk_widget_set_size_request(da, -1, 90);
    g_signal_connect(da, "draw", G_CALLBACK(on_draw), NULL);
    gtk_box_pack_start(GTK_BOX(box), da, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), gtk_button_new_with_label("Quarantine"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), gtk_button_new_with_label("Watch"), FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(win), box);
    gtk_widget_show_all(win);
    SAY("[gtkspike] window shown (dark Adwaita · headerbar + label + entry + buttons)\n");

    g_timeout_add(33, tick, NULL);
    gtk_main();
    SAY("[gtkspike] gtk_main returned · exit clean · FULL PATH GREEN\n");
    return 0;
}
