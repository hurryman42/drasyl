# Magic Numbers
This document contains a list of the magic numbers used by drasyl.

| Magic Number   | Description        | Location                                                                                                                                     |
|----------------|--------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| 507,465,729    | drasyl             | [RemoteMessage](drasyl-core/src/main/java/org/drasyl/handler/remote/protocol/RemoteMessage.java)                                             |
| -2,081,612,027 | TUN                | [TunnelWriteCodec](drasyl-cli/src/main/java/org/drasyl/cli/tunnel/handler/TunnelWriteCodec.java)                                             |
| 523,370,708    | Stop and Wait DATA | [StopAndWaitArqCodec](drasyl-core/src/main/java/org/drasyl/handler/arq/stopandwait/StopAndWaitArqCodec.java)                                 |
| 523,370,709    | Stop and Wait ACK  | [StopAndWaitArqCodec](drasyl-core/src/main/java/org/drasyl/handler/arq/stopandwait/StopAndWaitArqCodec.java)                                 |
| -143,591,473   | Chunking content   | [MessageChunkEncoder](drasyl-core/src/main/java/org/drasyl/handler/stream/MessageChunkEncoder.java)                                          |
| -143,591,472   | Chunking last      | [MessageChunkEncoder](drasyl-core/src/main/java/org/drasyl/handler/stream/MessageChunkEncoder.java)                                          |
| -578,611,194   | Groups joined      | [GroupsServerMessageEncoder](drasyl-plugin-groups-client/src/main/java/org/drasyl/node/plugin/groups/client/GroupsServerMessageEncoder.java) |
| -578,611,195   | Groups left        | [GroupsServerMessageEncoder](drasyl-plugin-groups-client/src/main/java/org/drasyl/node/plugin/groups/client/GroupsServerMessageEncoder.java) |
| -578,611,196   | Groups welcome     | [GroupsServerMessageEncoder](drasyl-plugin-groups-client/src/main/java/org/drasyl/node/plugin/groups/client/GroupsServerMessageEncoder.java) |
| -578,611,197   | Groups failed      | [GroupsServerMessageEncoder](drasyl-plugin-groups-client/src/main/java/org/drasyl/node/plugin/groups/client/GroupsServerMessageEncoder.java) |
| -376,669,039   | Probe              | [ProbeCodec](drasyl-cli/src/main/java/org/drasyl/cli/perf/handler/ProbeCodec.java)                                                           |
| 360,023,952    | GBN data           | [GoBackNArqCodec](drasyl-core/src/main/java/org/drasyl/handler/arq/gobackn/GoBackNArqCodec.java)                                             |
| 360,023,953    | GBN first data     | [GoBackNArqCodec](drasyl-core/src/main/java/org/drasyl/handler/arq/gobackn/GoBackNArqCodec.java)                                             |
| 360,023,954    | GBN reset          | [GoBackNArqCodec](drasyl-core/src/main/java/org/drasyl/handler/arq/gobackn/GoBackNArqCodec.java)                                             |
| 360,023,955    | GBN ACK            | [GoBackNArqCodec](drasyl-core/src/main/java/org/drasyl/handler/arq/gobackn/GoBackNArqCodec.java)                                             |
| 360,023,956    | GBN last data      | [GoBackNArqCodec](drasyl-core/src/main/java/org/drasyl/handler/arq/gobackn/GoBackNArqCodec.java)                                             |