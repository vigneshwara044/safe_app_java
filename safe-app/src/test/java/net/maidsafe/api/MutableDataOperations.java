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

import java.util.List;

import net.maidsafe.api.model.EncryptKeyPair;
import net.maidsafe.api.model.IpcReqError;
import net.maidsafe.api.model.IpcRequest;
import net.maidsafe.api.model.NativeHandle;
import net.maidsafe.api.model.Request;
import net.maidsafe.api.model.ShareMDataIpcRequest;
import net.maidsafe.safe_app.AppExchangeInfo;
import net.maidsafe.safe_app.AuthReq;
import net.maidsafe.safe_app.ContainerPermissions;
import net.maidsafe.safe_app.MDataEntry;
import net.maidsafe.safe_app.MDataInfo;
import net.maidsafe.safe_app.MDataKey;
import net.maidsafe.safe_app.MDataValue;
import net.maidsafe.safe_app.MetadataResponse;
import net.maidsafe.safe_app.PermissionSet;
import net.maidsafe.safe_app.ShareMData;
import net.maidsafe.safe_app.ShareMDataReq;
import net.maidsafe.safe_app.UserPermissionSet;
import net.maidsafe.test.utils.Helper;
import net.maidsafe.test.utils.SessionLoader;

import org.junit.Assert;
import org.junit.Test;



public class MutableDataOperations {
    static {
        SessionLoader.load();
    }
    public static final String APP_ID = "net.maidsafe.java.test";
    static final int LENGTH = 10;
    static final int TYPE_TAG = 15001;

    // Insert permissions, entries and 'put' the MD on the network.
    // Verify the inserted entries.
    // Perform update, delete operations and verify.
    // Serialise the MDInfo, deserialise it and verify the xorName and typeTag.
    // Verify permissions.
    // Modify the permission set and verify.
    private void publicMDataCrud(final MDataInfo mDataInfo, final Session session) throws Exception {
        PermissionSet permissionSet = new PermissionSet();
        permissionSet.setInsert(true);
        permissionSet.setUpdate(true);
        permissionSet.setRead(true);
        permissionSet.setDelete(true);
        permissionSet.setManagePermission(true);
        NativeHandle permissionHandle = session.mDataPermission.newPermissionHandle().get();
        session.mDataPermission.insert(permissionHandle,
                                       session.crypto.getAppPublicSignKey().get(),
                                       permissionSet).get();
        NativeHandle entriesHandle = session.mDataEntries.newEntriesHandle().get();

        String keyString = Helper.randomAlphaNumeric(LENGTH);
        String valueString = Helper.randomAlphaNumeric(LENGTH);

        session.mDataEntries.insert(entriesHandle, keyString.getBytes(),
                                    valueString.getBytes()).get();
        session.mData.put(mDataInfo, permissionHandle, entriesHandle).get();

        keyString = Helper.randomAlphaNumeric(LENGTH);
        valueString = Helper.randomAlphaNumeric(LENGTH);

        NativeHandle actionHandle = session.mDataEntryAction.newEntryAction().get();
        session.mDataEntryAction.insert(actionHandle, keyString.getBytes(),
                valueString.getBytes()).get();
        session.mData.mutateEntries(mDataInfo, actionHandle).get();

        entriesHandle = session.mData.getEntriesHandle(mDataInfo).get();
        List<MDataEntry> entries = session.mDataEntries.listEntries(entriesHandle).get();
        long length = session.mDataEntries.length(entriesHandle).get();
        Assert.assertEquals(length, entries.size());

        MDataValue mDataValue = session.mDataEntries.getValue(entriesHandle, keyString.getBytes()).get();
        Assert.assertEquals(new String(mDataValue.getContent()), valueString);

        actionHandle = session.mDataEntryAction.newEntryAction().get();
        MDataEntry entry = entries.get(0);
        byte[] updatedValue = Helper.randomAlphaNumeric(LENGTH).getBytes();
        session.mDataEntryAction.update(actionHandle, entry.getKey().getKey(), updatedValue,
                                        entry.getValue().getEntryVersion() + 1).get();
        session.mData.mutateEntries(mDataInfo, actionHandle).get();
        entriesHandle = session.mData.getEntriesHandle(mDataInfo).get();
        entries = session.mDataEntries.listEntries(entriesHandle).get();

        entry = entries.get(0);
        MDataValue value = session.mData.getValue(mDataInfo, entry.getKey().getKey()).get();
        Assert.assertEquals(new String(updatedValue), new String(value.getContent()));

        actionHandle = session.mDataEntryAction.newEntryAction().get();
        session.mDataEntryAction.delete(actionHandle, entry.getKey().getKey(),
                entry.getValue().getEntryVersion() + 1).get();
        session.mData.mutateEntries(mDataInfo, actionHandle).get();

        entriesHandle = session.mData.getEntriesHandle(mDataInfo).get();
        entries = session.mDataEntries.listEntries(entriesHandle).get();
        Assert.assertEquals(entries.get(0).getValue().getContentLen(), 0);

        byte[] serialisedMData = session.mData.serialise(mDataInfo).get();
        final MDataInfo mdInfo = session.mData.deserialise(serialisedMData).get();

        Assert.assertEquals(new String(mDataInfo.getName()), new String(mdInfo.getName()));
        Assert.assertEquals(mDataInfo.getTypeTag(), mdInfo.getTypeTag());

        List<MDataKey> keys = session.mData.getKeys(mdInfo).get();
        List<MDataValue> values = session.mData.getValues(mdInfo).get();
        Assert.assertEquals(keys.size(), values.size());
        Assert.assertEquals(new String(entries.get(0).getKey().getKey()),
                            new String(keys.get(0).getKey()));
        Assert.assertEquals(new String(entries.get(0).getValue().getContent()),
                            new String(values.get(0).getContent()));

        PermissionSet permissions = session.mData.getPermissionForUser(
                                    session.crypto.getAppPublicSignKey().get(), mdInfo).get();

        Assert.assertTrue(permissions.getInsert());
        Assert.assertTrue(permissions.getUpdate());
        Assert.assertTrue(permissions.getRead());
        Assert.assertTrue(permissions.getDelete());
        Assert.assertTrue(permissions.getManagePermission());

        permissionSet.setInsert(false);
        permissionSet.setUpdate(false);
        permissionSet.setRead(false);
        permissionSet.setDelete(false);
        permissionHandle = session.mDataPermission.newPermissionHandle().get();
        session.mDataPermission.insert(permissionHandle, session.crypto.getAppPublicSignKey().get(),
                                        permissionSet).get();
        session.mData.setUserPermission(session.crypto.getAppPublicSignKey().get(), mdInfo,
                                        permissionSet,
                                    session.mData.getVersion(mdInfo).get() + 1).get();
        long version = session.mData.getVersion(mdInfo).get();
        Assert.assertEquals(1, version);

        length = session.mData.getSerialisedSize(mDataInfo).get();
        Assert.assertTrue(length > 0);
    }

    // Insert permissions, encrypted entries and 'put' the MD on the network.
    // Decrypt and verify the inserted entries.
    // Perform update, delete operations and verify.
    // Serialise the MDInfo and deserialise ,verify the xorName and typeTag.
    private void privateMDataCrud(final MDataInfo mDataInfo, final Session session) throws Exception {
        PermissionSet permissionSet = new PermissionSet();
        permissionSet.setInsert(true);
        permissionSet.setUpdate(true);
        permissionSet.setRead(true);
        permissionSet.setDelete(true);
        NativeHandle permissionHandle = session.mDataPermission.newPermissionHandle().get();
        session.mDataPermission.insert(permissionHandle, session.crypto.getAppPublicSignKey().get(),
                                        permissionSet).get();
        NativeHandle entriesHandle = session.mDataEntries.newEntriesHandle().get();

        String keyString = Helper.randomAlphaNumeric(LENGTH);
        String valueString = Helper.randomAlphaNumeric(LENGTH);

        byte[] key = session.mData.encryptEntryKey(mDataInfo, keyString.getBytes()).get();
        byte[] value = session.mData.encryptEntryValue(mDataInfo, valueString.getBytes()).get();
        session.mDataEntries.insert(entriesHandle, key, value).get();
        session.mData.put(mDataInfo, permissionHandle, entriesHandle).get();

        keyString = Helper.randomAlphaNumeric(LENGTH);
        valueString = Helper.randomAlphaNumeric(LENGTH);

        NativeHandle actionHandle = session.mDataEntryAction.newEntryAction().get();
        key = session.mData.encryptEntryKey(mDataInfo, keyString.getBytes()).get();
        value = session.mData.encryptEntryValue(mDataInfo, valueString.getBytes()).get();
        session.mDataEntryAction.insert(actionHandle, key, value).get();
        session.mData.mutateEntries(mDataInfo, actionHandle).get();

        entriesHandle = session.mData.getEntriesHandle(mDataInfo).get();
        List<MDataEntry> entries = session.mDataEntries.listEntries(entriesHandle).get();
        long length = session.mDataEntries.length(entriesHandle).get();
        Assert.assertEquals(length, entries.size());

        key = session.mData.encryptEntryKey(mDataInfo, keyString.getBytes()).get();
        MDataValue mDataValue = session.mDataEntries.getValue(entriesHandle, key).get();
        byte[] decryptedValue = session.mData.decrypt(mDataInfo, mDataValue.getContent()).get();
        Assert.assertEquals(new String(decryptedValue), valueString);

        actionHandle = session.mDataEntryAction.newEntryAction().get();
        MDataEntry entry = entries.get(0);
        byte[] updatedValue = Helper.randomAlphaNumeric(LENGTH).getBytes();
        byte[] encryptedUpdatedValue = session.mData.encryptEntryValue(mDataInfo, updatedValue).get();
        session.mDataEntryAction.update(actionHandle, entry.getKey().getKey(), encryptedUpdatedValue,
                entry.getValue().getEntryVersion() + 1).get();
        session.mData.mutateEntries(mDataInfo, actionHandle).get();

        MDataValue entryValue = session.mData.getValue(mDataInfo, entry.getKey().getKey()).get();
        decryptedValue = session.mData.decrypt(mDataInfo, entryValue.getContent()).get();
        Assert.assertEquals(new String(updatedValue), new String(decryptedValue));

        entriesHandle = session.mData.getEntriesHandle(mDataInfo).get();
        entries = session.mDataEntries.listEntries(entriesHandle).get();

        entry = entries.get(0);
        actionHandle = session.mDataEntryAction.newEntryAction().get();
        session.mDataEntryAction.delete(actionHandle, entry.getKey().getKey(),
                entry.getValue().getEntryVersion() + 1).get();
        session.mData.mutateEntries(mDataInfo, actionHandle).get();

        entriesHandle = session.mData.getEntriesHandle(mDataInfo).get();
        entries = session.mDataEntries.listEntries(entriesHandle).get();
        Assert.assertEquals(0, entries.get(0).getValue().getContentLen());

        byte[] serialisedMData = session.mData.serialise(mDataInfo).get();
        final MDataInfo mdInfo = session.mData.deserialise(serialisedMData).get();

        Assert.assertEquals(new String(mDataInfo.getName()), new String(mdInfo.getName()));
        Assert.assertEquals(mDataInfo.getTypeTag(), mdInfo.getTypeTag());

        entriesHandle = session.mData.getEntriesHandle(mdInfo).get();
        entries = session.mDataEntries.listEntries(entriesHandle).get();
        Assert.assertEquals(2, entries.size());

        length = session.mData.getSerialisedSize(mDataInfo).get();
        Assert.assertTrue(length > 0);
    }

    // Create a random public MD.
    // Perform CRUD operations.
    @Test
    public void shouldMutateRandomPublicData() throws Exception {
        Session session = TestHelper.createSession();
        MDataInfo mDataInfo = session.mData.getRandomPublicMData(TYPE_TAG).get();
        publicMDataCrud(mDataInfo, session);
    }

    // Create a public MD at a specific location.
    // Perform CRUD operations.
    @Test
    public void shouldMutatePublicData() throws Exception {
        Session session = TestHelper.createSession();
        MDataInfo mDataInfo = new MDataInfo();
        mDataInfo.setName(Helper.randomAlphaNumeric(Constants.XOR_NAME_LENGTH).getBytes());
        mDataInfo.setTypeTag(TYPE_TAG);
        publicMDataCrud(mDataInfo, session);
    }

    // Create random private MD with generated nonce and secret key.
    // Perform CRUD operations.
    @Test
    public void shouldMutateRandomPrivateData() throws Exception {
        Session session = TestHelper.createSession();
        MDataInfo mDataInfo = session.mData.getRandomPrivateMData(TYPE_TAG).get();
        privateMDataCrud(mDataInfo, session);
    }

    // Create private MD with generated keyPair, nonce and secret key.
    // Perform CRUD operations.
    @Test
    public void shouldMutatePrivateData() throws Exception {
        Session session = TestHelper.createSession();
        EncryptKeyPair encryptKeyPair = session.crypto.generateEncryptKeyPair().get();
        byte[] nonce = session.crypto.generateNonce().get();
        byte[] secretKey = session.crypto.getRawSecretEncryptKey(encryptKeyPair.getSecretEncryptKey()).get();
        MDataInfo mDataInfo = session.mData.getPrivateMData(
                                        Helper.randomAlphaNumeric(Constants.XOR_NAME_LENGTH).getBytes(),
                                        TYPE_TAG, secretKey, nonce).get();
        privateMDataCrud(mDataInfo, session);
    }

    // Create a MD and insert permissions for all and for a particular app.
    // 'Put' the data on the network.
    // Fetch the permissions and verify.
    // Update the permissions.
    // Delete a user's permissions and verify.
    @Test
    public void shouldManagePermissionsForMutableData() throws Exception {
        Session session = TestHelper.createSession();
        MDataInfo mDataInfo = session.mData.getRandomPublicMData(TYPE_TAG).get();

        PermissionSet permissionSet = new PermissionSet();
        permissionSet.setRead(true);
        permissionSet.setInsert(true);
        NativeHandle permissionHandle = session.mDataPermission.newPermissionHandle().get();
        session.mDataPermission.insert(permissionHandle, Constants.USER_ANYONE,
                                       permissionSet).get();

        permissionSet.setUpdate(true);
        permissionSet.setDelete(true);
        permissionSet.setManagePermission(true);

        NativeHandle appPublicSignKey = session.crypto.getAppPublicSignKey().get();
        session.mDataPermission.insert(permissionHandle, appPublicSignKey,
                                       permissionSet).get();

        session.mData.put(mDataInfo, permissionHandle, Constants.MD_ENTRIES_EMPTY).get();

        NativeHandle fetchedPermissionHandle = session.mData.getPermission(mDataInfo).get();
        PermissionSet fetchedPermissionSet = session.mDataPermission.getPermissionForUser(
                                                                            fetchedPermissionHandle,
                                                                            appPublicSignKey).get();

        Assert.assertTrue(fetchedPermissionSet.getRead());
        Assert.assertTrue(fetchedPermissionSet.getInsert());
        Assert.assertTrue(fetchedPermissionSet.getUpdate());
        Assert.assertTrue(fetchedPermissionSet.getDelete());
        Assert.assertTrue(fetchedPermissionSet.getManagePermission());

        permissionSet.setDelete(false);
        session.mData.setUserPermission(appPublicSignKey, mDataInfo, permissionSet,
                                 session.mData.getVersion(mDataInfo).get() + 1).get();

        PermissionSet newPermissionSet = session.mData.getPermissionForUser(appPublicSignKey,
                                                                            mDataInfo).get();
        Assert.assertEquals(newPermissionSet.getDelete(), false);

        permissionHandle = session.mData.getPermission(mDataInfo).get();
        long noOfPermissions = session.mDataPermission.getLength(permissionHandle).get();
        List<UserPermissionSet> userPermissionSet = session.mDataPermission.listAll(
                                                                            permissionHandle).get();
        Assert.assertEquals(noOfPermissions, userPermissionSet.size());

        session.mData.deleteUserPermission(Constants.USER_ANYONE, mDataInfo,
                session.mData.getVersion(mDataInfo).get() + 1).get();
        permissionHandle = session.mData.getPermission(mDataInfo).get();
        userPermissionSet = session.mDataPermission.listAll(permissionHandle).get();
        Assert.assertEquals(userPermissionSet.size(), 1);
    }

    // Create a authenticator and authenticate an application 'appA'.
    // Create a MD in appA, encode metadata and insert it as an entry.
    // 'Put' the data on the network and terminate app A's session.
    // Create a session for app B and send a shared MD request for the MD created by app A.
    // Verify that the metadata is fetched and decoded correctly by the authenticator. Allow the shared MD request.
    // Verify that App B is able to mutate the MD created by app A.

    @Test
    public void shouldShareMutableData() throws Exception {
        MetadataResponse metadataResponse;
        String keyString, valueString;
        MDataInfo mDataInfo;
        Authenticator authenticator = TestHelper.createAuthenticator();
        ContainerPermissions[] permissions = new ContainerPermissions[1];
        permissions[0] = new ContainerPermissions("_public", new PermissionSet(true, true,
                true, true, true));

        AuthReq authReq = new AuthReq(new AppExchangeInfo(APP_ID, "",
                    Helper.randomAlphaNumeric(LENGTH), Helper.randomAlphaNumeric(LENGTH)),
                    true, permissions, 1, 0);
        try {
            Session appA = TestHelper.handleAuthReq(authenticator, authReq);

            mDataInfo = new MDataInfo();
            mDataInfo.setName(Helper.randomAlphaNumeric(Constants.XOR_NAME_LENGTH).getBytes());
            mDataInfo.setTypeTag(TYPE_TAG);

            keyString = Helper.randomAlphaNumeric(LENGTH);
            valueString = Helper.randomAlphaNumeric(LENGTH);
            NativeHandle entriesHandle = appA.mDataEntries.newEntriesHandle().get();
            byte[] key = appA.mData.encryptEntryKey(mDataInfo, keyString.getBytes()).get();
            byte[] value = appA.mData.encryptEntryValue(mDataInfo, valueString.getBytes()).get();
            appA.mDataEntries.insert(entriesHandle, key, value).get();

            metadataResponse = new MetadataResponse();
            metadataResponse.setName("Test MData");
            metadataResponse.setDescription("MData for testing");
            metadataResponse.setXorName(mDataInfo.getName());
            metadataResponse.setTypeTag(mDataInfo.getTypeTag());
            byte[] encodedResponse = appA.mData.encodeMetadata(metadataResponse).get();

            appA.mDataEntries.insert(entriesHandle, Constants.MD_METADATA_KEY.getBytes(), encodedResponse).get();
            appA.mData.put(mDataInfo, Constants.MD_PERMISSION_EMPTY, entriesHandle).get();

        } catch (Exception e) {
            throw e;
        }

        authReq.getApp().setId("net.maidsafe.app.two");
        Session appB = TestHelper.handleAuthReq(authenticator, authReq);
        Request shareMDataIpcRequest;
        AppExchangeInfo appExchangeInfo = new AppExchangeInfo("net.maidsafe.app.two",
                                                "", "App two", "Maidsafe.net");
        ShareMData[] shareMData = new ShareMData[1];
        shareMData[0] =  new ShareMData(mDataInfo.getTypeTag(),
                                mDataInfo.getName(), new PermissionSet(true, true, true,
                                true, false));

        ShareMDataReq shareMDataReq = new ShareMDataReq(appExchangeInfo, shareMData, 1, 1);
        shareMDataIpcRequest =  Session.getShareMutableDataRequest(shareMDataReq).get();

        IpcRequest decodedReq = authenticator.decodeIpcMessage(shareMDataIpcRequest.getUri()).get();
        if (decodedReq.getClass().equals(IpcReqError.class)) {
            IpcReqError error = (IpcReqError) decodedReq;
            throw new Exception(error.getMessage() + " \n " + error.getDescription());
        }
        ShareMDataIpcRequest shareMDataIpcReq = (ShareMDataIpcRequest) decodedReq;

        Assert.assertEquals(shareMDataIpcReq.getMetadataResponse().length, 1);
        Assert.assertEquals(shareMDataIpcReq.getMetadataResponse()[0].getDescription(),
                            metadataResponse.getDescription());
        Assert.assertEquals(shareMDataIpcReq.getMetadataResponse()[0].getName(),
                            metadataResponse.getName());
        Assert.assertEquals(new String(shareMDataIpcReq.getMetadataResponse()[0].getXorName()),
                            new String(metadataResponse.getXorName()));
        Assert.assertEquals(shareMDataIpcReq.getMetadataResponse()[0].getTypeTag(),
                            metadataResponse.getTypeTag());

        authenticator.encodeShareMDataResponse(shareMDataIpcReq, true).get();

        NativeHandle actionHandle = appB.mDataEntryAction.newEntryAction().get();
        keyString = Helper.randomAlphaNumeric(LENGTH);
        valueString = Helper.randomAlphaNumeric(LENGTH);
        appB.mDataEntryAction.insert(actionHandle, keyString.getBytes(), valueString.getBytes()).get();
        appB.mData.mutateEntries(mDataInfo, actionHandle).get();

        MDataValue mDataValue = appB.mData.getValue(mDataInfo, keyString.getBytes()).get();
        Assert.assertEquals(valueString, new String(mDataValue.getContent()));
    }
}
