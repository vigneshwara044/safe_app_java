// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.
package net.maidsafe.api;

import net.maidsafe.api.model.AuthIpcRequest;
import net.maidsafe.api.model.AuthResponse;
import net.maidsafe.api.model.DecodeResult;
import net.maidsafe.api.model.EncryptKeyPair;
import net.maidsafe.api.model.IpcRequest;
import net.maidsafe.api.model.Request;
import net.maidsafe.safe_app.AppExchangeInfo;
import net.maidsafe.safe_app.AuthReq;
import net.maidsafe.safe_app.ContainerPermissions;
import net.maidsafe.safe_app.PermissionSet;
import net.maidsafe.test.utils.Helper;
import net.maidsafe.test.utils.SessionLoader;

import org.junit.Assert;
import org.junit.Test;

public class ClientTest {

    static {
        SessionLoader.load();
    }

    public static final String APP_ID = "net.maidsafe.java.test";
    public static final int LENGTH = 10;

    @Test
    public void unregisteredAccessTest() throws Exception {
        Session unregisteredSession = TestHelper.createUnregisteredSession();
        EncryptKeyPair encryptKeyPair = unregisteredSession.crypto.generateEncryptKeyPair().get();
        Assert.assertNotNull(encryptKeyPair);
        byte[] cipherText = unregisteredSession.crypto.encrypt(encryptKeyPair.getPublicEncryptKey(),
                encryptKeyPair.getSecretEncryptKey(), "Hello".getBytes()).get();
        Assert.assertEquals("Hello", new String(
                unregisteredSession.crypto.decrypt(encryptKeyPair.getPublicEncryptKey(),
                        encryptKeyPair.getSecretEncryptKey(), cipherText).get()));
    }

    @Test
    public void disconnectionTest() throws Exception {
        Session client = TestHelper.createSession();
        client.setOnDisconnectListener(o -> {
            Assert.assertFalse(client.isConnected());
            try {
                client.reconnect().get();
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException("Unable to reconnect");
            }
        });
        client.testSimulateDisconnect().get();
    }

    @Test
    public void containerTest() throws Exception {
        Session session = TestHelper.createSession();

        ContainerPermissions[] permissions = new ContainerPermissions[1];
        permissions[0] = new ContainerPermissions("_public", new PermissionSet(true,
                true, true, true, true));
        AuthReq authReq = new AuthReq(new AppExchangeInfo(APP_ID, "",
                Helper.randomAlphaNumeric(LENGTH), Helper.randomAlphaNumeric(LENGTH)),
                true, permissions, 1, 0);
        String locator = Helper.randomAlphaNumeric(LENGTH);
        String secret = Helper.randomAlphaNumeric(LENGTH);

        Authenticator authenticator = Authenticator.createAccount(locator, secret,
                Helper.randomAlphaNumeric(LENGTH)).get();
        Request request = Session.encodeAuthReq(authReq).get();
        IpcRequest ipcRequest = authenticator.decodeIpcMessage(request.getUri()).get();
        AuthIpcRequest authIpcRequest = (AuthIpcRequest) ipcRequest;
        String response = authenticator.encodeAuthResponse(authIpcRequest,
                true).get();
        DecodeResult decodeResult = Session.decodeIpcMessage(response).get();
        AuthResponse authResponse = (AuthResponse) decodeResult;



    }
}
