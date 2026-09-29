"""Atomic NetworkManager publication through libnm and its D-Bus API."""

import ctypes as C


def publish_keyfile(text: str) -> None:
    """Validate offline, then publish with TO_DISK and BLOCK_AUTOCONNECT."""
    pointer, string, integer, unsigned = C.c_void_p, C.c_char_p, C.c_int, C.c_uint
    glib = C.CDLL("libglib-2.0.so.0")
    gio = C.CDLL("libgio-2.0.so.0")
    gobject = C.CDLL("libgobject-2.0.so.0")
    nm = C.CDLL("libnm.so.0")

    def bind(library, name, result, *arguments):
        function = getattr(library, name)
        function.restype, function.argtypes = result, arguments
        return function

    key_new = bind(glib, "g_key_file_new", pointer)
    key_load = bind(glib, "g_key_file_load_from_data", integer, pointer, string,
                    C.c_size_t, integer, pointer)
    key_free = bind(glib, "g_key_file_unref", None, pointer)
    read = bind(nm, "nm_keyfile_read", pointer, pointer, string, unsigned,
                pointer, pointer, pointer)
    verify = bind(nm, "nm_connection_verify", integer, pointer, pointer)
    verify_secrets = bind(nm, "nm_connection_verify_secrets", integer, pointer, pointer)
    serialize = bind(nm, "nm_connection_to_dbus", pointer, pointer, unsigned)
    parse = bind(glib, "g_variant_parse", pointer, pointer, string, pointer, pointer, pointer)
    uint = bind(glib, "g_variant_new_uint32", pointer, unsigned)
    tuple_new = bind(glib, "g_variant_new_tuple", pointer, C.POINTER(pointer), C.c_size_t)
    sink = bind(glib, "g_variant_ref_sink", pointer, pointer)
    unref = bind(glib, "g_variant_unref", None, pointer)
    object_unref = bind(gobject, "g_object_unref", None, pointer)
    bus_get = bind(gio, "g_bus_get_sync", pointer, integer, pointer, pointer)
    call = bind(gio, "g_dbus_connection_call_sync", pointer, pointer, string, string,
                string, string, pointer, pointer, integer, integer, pointer, pointer)

    key = key_new()
    connection = settings = parameters = extra = bus = reply = None
    try:
        data = text.encode("utf-8")
        # GLib errors can quote secret values, so expose only fixed messages.
        if not key_load(key, data, len(data), 0, None):
            raise ValueError("invalid NetworkManager keyfile")
        connection = read(key, b"/", 0, None, None, None)
        if not connection or not verify(connection, None) or not verify_secrets(connection, None):
            raise ValueError("invalid NetworkManager WireGuard settings")
        settings = sink(serialize(connection, 0))
        extra = parse(None, b"@a{sv} {}", None, None, None)
        parameters = sink(tuple_new(
            (pointer * 3)(settings, uint(0x1 | 0x20), extra), 3))
        bus = bus_get(1, None, None)
        if not bus:
            raise ValueError("NetworkManager system bus unavailable")
        reply = call(bus, b"org.freedesktop.NetworkManager",
                     b"/org/freedesktop/NetworkManager/Settings",
                     b"org.freedesktop.NetworkManager.Settings", b"AddConnection2",
                     parameters, None, 0, 10000, None, None)
        if not reply:
            raise ValueError("NetworkManager atomic profile publication failed")
    finally:
        if reply:
            unref(reply)
        if bus:
            object_unref(bus)
        if parameters:
            unref(parameters)
        if settings:
            unref(settings)
        if extra:
            unref(extra)
        if connection:
            object_unref(connection)
        key_free(key)
