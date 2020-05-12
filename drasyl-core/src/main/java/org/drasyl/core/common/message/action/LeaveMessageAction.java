package org.drasyl.core.common.message.action;

import org.drasyl.core.common.message.LeaveMessage;
import org.drasyl.core.common.message.StatusMessage;
import org.drasyl.core.node.connections.ClientConnection;
import org.drasyl.core.server.NodeServer;

import static org.drasyl.core.common.message.StatusMessage.Code.STATUS_OK;

public class LeaveMessageAction extends AbstractMessageAction<LeaveMessage> implements ServerMessageAction<LeaveMessage> {
    public LeaveMessageAction(LeaveMessage message) {
        super(message);
    }

    @Override
    public void onMessageServer(ClientConnection session,
                                NodeServer nodeServer) {
        session.send(new StatusMessage(STATUS_OK, message.getId()));
        session.close();
    }
}
