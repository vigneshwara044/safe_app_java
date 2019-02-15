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

import net.maidsafe.api.model.App;
import net.maidsafe.api.model.AuthIpcRequest;
import net.maidsafe.api.model.AuthResponse;
import net.maidsafe.api.model.DecodeResult;
import net.maidsafe.api.model.EncryptKeyPair;
import net.maidsafe.api.model.IpcRequest;
import net.maidsafe.api.model.NativeHandle;
import net.maidsafe.api.model.Request;
import net.maidsafe.safe_app.AccessContInfo;
import net.maidsafe.safe_app.AccountInfo;
import net.maidsafe.safe_app.AppExchangeInfo;
import net.maidsafe.safe_app.AuthReq;
import net.maidsafe.safe_app.ContainerPermissions;
import net.maidsafe.safe_app.MDataInfo;
import net.maidsafe.safe_app.PermissionSet;
import net.maidsafe.test.utils.Helper;
import net.maidsafe.test.utils.SessionLoader;

import org.junit.Assert;
import org.junit.Test;

import static net.maidsafe.api.MDataTest.TYPE_TAG;

public class ClientTest {

    static {
        SessionLoader.load();
    }

    public static final String APP_ID = "net.maidsafe.java.test";
    private static final String APP_CONTAINER_NAME = "apps/";
    public static final int LENGTH = 10;
    final App app = new App("net.maidsafe.sample", "Safe ToDo",
            "Maidsafe.net", "0.1.0");

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

        Session session = Session.connect(authReq.getApp().getId(), authResponse.getAuthGranted()).get();

        MDataInfo containerMDataInfo = session.getContainerMDataInfo("_public").get();


        System.out.println(containerMDataInfo.getName().toString());
        System.out.println(containerMDataInfo.getTypeTag());
        System.out.println(containerMDataInfo.getHasEncInfo());

    }

    @Test
    public void logTest() throws Exception {

        // create a session and set up the app container.

        ContainerPermissions[] permissions = new ContainerPermissions[1];
        permissions[0] = new ContainerPermissions(APP_CONTAINER_NAME + APP_ID, new PermissionSet(true,
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

        Session session = Session.connect(authReq.getApp().getId(), authResponse.getAuthGranted()).get();

        // copy the log.toml file and safe-core.config file with unlimited mutations to a folder.

        // use getAppStem and fetch the expected name for the app’s executable without extension.

        String appName = session.getAppStem().get();

        // set the additional search paths and initialize logging.
        session.initLogging("sample.txt");

        String logOutputPath = session.getLogOutputPath("sample.txt").get();

        MDataInfo containerMDI = session.getContainerMDataInfo("apps/id").get();

        long tagType = TYPE_TAG;
        MDataInfo mDataInfo = new MDataInfo();
        mDataInfo.setName(Helper.randomAlphaNumeric(Constants.XOR_NAME_LENGTH).getBytes());
        mDataInfo.setTypeTag(tagType);

        NativeHandle entriesHandle = session.mDataEntries.newEntriesHandle().get();
        byte[] key = session.mData.encryptEntryKey(mDataInfo, "SAFERocks-key1".getBytes()).get();
        byte[] value = session.mData.encryptEntryValue(mDataInfo, ("" +
                "SAFERocks-value2").getBytes()).get();

        //inserting the entries handle
        session.mDataEntries.insert(entriesHandle, key, value).get();

        session.mData.put(mDataInfo, Constants.MD_PERMISSION_EMPTY, entriesHandle).get();

        AccountInfo accountInfo = session.getAccountInfo().get();

        long mutationAvailable = accountInfo.getMutationsAvailable();

        long mutationsDone =  accountInfo.getMutationsDone();

        System.out.println(mutationAvailable);
        System.out.println(mutationsDone);


    }
}
