// The descriptors protoc-gen-es 2.16.0 wrote (made with buf 1.74.0) for python/tests/fixtures/protobuf_es/proto/
// (proto3 with an import, a map, a oneof and a service; proto2 with defaults, an extension range, reserved names,
// a packed field and an extension; edition 2023 with features; a status enum with many file options) and for a
// .proto file of custom message-typed options (made up as they are; inert).

pub const PROTO3: &str = concat!(
    "CiZsaXN0ZW50b2dldGhlci92MS9saXN0ZW50b2dldGhlci5wcm90bxIRbGlzdGVudG9nZXRoZXIudjEilAMKBFJvb20SCgoCaWQY",
    "ASABKAkSDAoEbmFtZRgCIAEoCRIqCgdtZW1iZXJzGAMgAygLMhkubGlzdGVudG9nZXRoZXIudjEuTWVtYmVyEi0KC25vd19wbGF5",
    "aW5nGAQgASgLMhgubGlzdGVudG9nZXRoZXIudjEuVHJhY2sSLgoKY3JlYXRlZF9hdBgFIAEoCzIaLmdvb2dsZS5wcm90b2J1Zi5U",
    "aW1lc3RhbXASMwoGbGFiZWxzGAYgAygLMiMubGlzdGVudG9nZXRoZXIudjEuUm9vbS5MYWJlbHNFbnRyeRIrCgZwYXVzZWQYByAB",
    "KAsyGS5saXN0ZW50b2dldGhlci52MS5QYXVzZWRIABItCgdwbGF5aW5nGAggASgLMhoubGlzdGVudG9nZXRoZXIudjEuUGxheWlu",
    "Z0gAEh4KBnN0YXR1cxgJIAEoDjIOLmNvbW1vbi5TdGF0dXMaLQoLTGFiZWxzRW50cnkSCwoDa2V5GAEgASgJEg0KBXZhbHVlGAIg",
    "ASgJOgI4AUIHCgVzdGF0ZSI9CgZNZW1iZXISDwoHdXNlcl9pZBgBIAEoCRIUCgxkaXNwbGF5X25hbWUYAiABKAkSDAoEaG9zdBgD",
    "IAEoCCJICgVUcmFjaxILCgN1cmkYASABKAkSDQoFdGl0bGUYAiABKAkSDgoGYXJ0aXN0GAMgASgJEhMKC2R1cmF0aW9uX21zGAQg",
    "ASgNIh0KBlBhdXNlZBITCgtwb3NpdGlvbl9tcxgBIAEoDSJJCgdQbGF5aW5nEhMKC3Bvc2l0aW9uX21zGAEgASgNEikKBXNpbmNl",
    "GAIgASgLMhouZ29vZ2xlLnByb3RvYnVmLlRpbWVzdGFtcCI0CgtKb2luUmVxdWVzdBIPCgdyb29tX2lkGAEgASgJEhQKDGRpc3Bs",
    "YXlfbmFtZRgCIAEoCSI1CgxKb2luUmVzcG9uc2USJQoEcm9vbRgBIAEoCzIXLmxpc3RlbnRvZ2V0aGVyLnYxLlJvb20ikgEKCVN5",
    "bmNFdmVudBInCgRyb29tGAEgASgLMhcubGlzdGVudG9nZXRoZXIudjEuUm9vbUgAEikKBXRyYWNrGAIgASgLMhgubGlzdGVudG9n",
    "ZXRoZXIudjEuVHJhY2tIABIpCgRsZWZ0GAMgASgLMhkubGlzdGVudG9nZXRoZXIudjEuTWVtYmVySABCBgoEa2luZCo+CgRSb2xl",
    "EhQKEFJPTEVfVU5TUEVDSUZJRUQQABIRCg1ST0xFX0xJU1RFTkVSEAESDQoJUk9MRV9IT1NUEAIyqAEKFUxpc3RlblRvZ2V0aGVy",
    "U2VydmljZRJHCgRKb2luEh4ubGlzdGVudG9nZXRoZXIudjEuSm9pblJlcXVlc3QaHy5saXN0ZW50b2dldGhlci52MS5Kb2luUmVz",
    "cG9uc2USRgoEU3luYxIeLmxpc3RlbnRvZ2V0aGVyLnYxLkpvaW5SZXF1ZXN0GhwubGlzdGVudG9nZXRoZXIudjEuU3luY0V2ZW50",
    "MAFCSlpIZXhhbXBsZS5pbnZhbGlkL2xpc3RlbnRvZ2V0aGVyL2dlbi9nby9saXN0ZW50b2dldGhlci92MTtsaXN0ZW50b2dldGhl",
    "cnYxYgZwcm90bzM",
);

pub const PROTO2: &str = concat!(
    "ChVsZWdhY3kvc2V0dGluZ3MucHJvdG8SD2xlZ2FjeS5zZXR0aW5ncyLzAQoIU2V0dGluZ3MSHgoIZ3JlZXRpbmcYASABKAk6DGhl",
    "bGxvLCB3b3JsZBISCgdyZXRyaWVzGAIgASgFOgEzEhcKBW1hZ2ljGAMgASgMOghcMDAxXDAwMhISCgVyYXRpbxgEIAEoAToDMC41",
    "Eg8KA2lkcxgFIAMoBUICEAESNwoEbW9kZRgGIAEoDjIeLmxlZ2FjeS5zZXR0aW5ncy5TZXR0aW5ncy5Nb2RlOglNT0RFX0ZBU1Qi",
    "JAoETW9kZRINCglNT0RFX1NMT1cQABINCglNT0RFX0ZBU1QQASoFCGQQyAFKBAgyED1SCW9sZF9maWVsZDotCgRub3RlEhkubGVn",
    "YWN5LnNldHRpbmdzLlNldHRpbmdzGGQgASgJUgRub3Rl",
);

pub const EDITION: &str = concat!(
    "ChBlZC9lZGl0aW9uLnByb3RvEgVlZC52MSJbCgVUaGluZxIMCgRuYW1lGAEgASgJEhQKBWNvdW50GAIgASgFQgWqAQIIARIMCgR0",
    "YWdzGAMgAygJEiAKBGtpbmQYBCABKA4yCy5lZC52MS5LaW5kQgWqAQIIASokCgRLaW5kEgoKBktJTkRfQRAAEgoKBktJTkRfQhAB",
    "GgQ6AhACQgWSAwIIAmIIZWRpdGlvbnNw6Ac",
);

pub const OPTIONS: &str = concat!(
    "Cg9vcHRzL2RvY3MucHJvdG8SB29wdHMudjEiUgoGQXBpRG9jEg8KB3N1bW1hcnkYASABKAkSEwoLZGVzY3JpcHRpb24YAiABKAkS",
    "DAoEdGFncxgDIAMoCRIUCgxleHRlcm5hbF91cmwYBCABKAkirgIKBFBpbmcSDwoHcGF5bG9hZBgBIAEoCTqUApK1GI8CCgZBIHBp",
    "bmcSwwFTZW5kcyBhIHBpbmcgdG8gdGhlIHNlcnZlciBhbmQgd2FpdHMgZm9yIHRoZSBhbnN3ZXI7IHRoZSBzZXJ2ZXIgYW5zd2Vy",
    "cyB3aXRoIHRoZSBzYW1lIHBheWxvYWQgc28gdGhhdCBhIGNsaWVudCBjYW4gbWVhc3VyZSB0aGUgcm91bmQgdHJpcCB0aW1lIG9m",
    "IHRoZSBjb25uZWN0aW9uLCBpbmNsdWRpbmcgYW55IHByb3hpZXMgb24gdGhlIHdheS4aBmhlYWx0aBoLZGlhZ25vc3RpY3MaB25l",
    "dHdvcmsiIWh0dHBzOi8vZG9jcy5leGFtcGxlLmludmFsaWQvcGluZzLLAgoLUGluZ1NlcnZpY2USuwIKBFBpbmcSDS5vcHRzLnYx",
    "LlBpbmcaDS5vcHRzLnYxLlBpbmcilAKKtRiPAgoPUGluZyB0aGUgc2VydmVyEsMBU2VuZHMgYSBwaW5nIHRvIHRoZSBzZXJ2ZXIg",
    "YW5kIHdhaXRzIGZvciB0aGUgYW5zd2VyOyB0aGUgc2VydmVyIGFuc3dlcnMgd2l0aCB0aGUgc2FtZSBwYXlsb2FkIHNvIHRoYXQg",
    "YSBjbGllbnQgY2FuIG1lYXN1cmUgdGhlIHJvdW5kIHRyaXAgdGltZSBvZiB0aGUgY29ubmVjdGlvbiwgaW5jbHVkaW5nIGFueSBw",
    "cm94aWVzIG9uIHRoZSB3YXkuGgZoZWFsdGgaC2RpYWdub3N0aWNzIiFodHRwczovL2RvY3MuZXhhbXBsZS5pbnZhbGlkL3Bpbmc6",
    "SgoHYXBpX2RvYxIeLmdvb2dsZS5wcm90b2J1Zi5NZXRob2RPcHRpb25zGNGGAyABKAsyDy5vcHRzLnYxLkFwaURvY1IGYXBpRG9j",
    "OksKB21zZ19kb2MSHy5nb29nbGUucHJvdG9idWYuTWVzc2FnZU9wdGlvbnMY0oYDIAEoCzIPLm9wdHMudjEuQXBpRG9jUgZtc2dE",
    "b2NiBnByb3RvMw",
);

pub const FILE_OPTIONS: &str = concat!(
    "ChNjb21tb24vY29tbW9uLnByb3RvEgZjb21tb24qLwoGU3RhdHVzEhYKElNUQVRVU19VTlNQRUNJRklFRBAAEg0KCVNUQVRVU19P",
    "SxABQtQBCiFjb20uZXhhbXBsZS5saXN0ZW50b2dldGhlci5jb21tb25CC0NvbW1vblByb3RvUAFaM2V4YW1wbGUuaW52YWxpZC9s",
    "aXN0ZW50b2dldGhlci9nZW4vZ28vY29tbW9uO2NvbW1vbqICA0NYWKoCHUV4YW1wbGUuTGlzdGVudG9nZXRoZXIuQ29tbW9uugIC",
    "TFTKAh1FeGFtcGxlXExpc3RlbnRvZ2V0aGVyXENvbW1vbuoCH0V4YW1wbGU6Okxpc3RlbnRvZ2V0aGVyOjpDb21tb25iBnByb3Rv",
    "Mw",
);
